> **Status:** everything below is now integrated (delta.js, offscreen.hardening.js,
> pii.hardening.js, client validation from background.hardening.js). Kept as the
> design record; see README.md §4 for current status and measurements.

# AAVARAN — Hardening Pass

## 0. The blocker first

Your logs have said the same thing every run:

```
libs/worker.min.js: 0 bytes (expected >= 10000)
libs/tesseract-core.wasm.js: 0 bytes (expected >= 100000)
```

Neither of those two files was in any of the download commands you were given.

| file | where it actually lives |
|---|---|
| `worker.min.js` | `tesseract.js@5/**dist**/worker.min.js` — never fetched |
| `tesseract-core.wasm.js` | package **`tesseract.js-core`**, a *different* npm package — never fetched |
| `tesseract-core.wasm` | same package; the `.wasm.js` above is emscripten glue that fetches this at runtime. Your preflight doesn't even check for it, so libs/ could "pass" while still being unusable |

Two secondary problems in the same commands:

- In PowerShell, `curl` is an alias for `Invoke-WebRequest`, so `curl -L <url> -o <path>` does not parse. That is how you got files with the right names and zero bytes.
- `tinyFaceDetector` has exactly **one** shard. Downloading `tiny_face_detector_model-shard2` saves a GitHub 404 page to disk, which is what produced `face_detection_failed: Failed to fetch`.

### Fix

```powershell
powershell -ExecutionPolicy Bypass -File .\fetch-libs.ps1 -ExtensionRoot D:\aavaran\extension -Clean
```

It pins versions, retries with backoff, writes to `.part` and only renames on a size check, then prints a size table. Expect roughly:

```
tesseract.min.js                 ~  63,000
worker.min.js                    ~  60,000
tesseract-core.wasm.js           ~ 220,000
tesseract-core.wasm              ~3,600,000
tessdata/eng.traineddata         ~4,100,000
face-api.min.js                  ~ 700,000
models/..._manifest.json         ~   1,000
models/..._shard1                ~ 190,000
```

It uses **`tessdata_fast`**, not `tessdata`. tesseract.js v5 runs LSTM only, so the 23 MB legacy+LSTM file is 19 MB of dead weight and a much slower worker init.

### Two things the script can't do for you

**manifest.json** — wasm will not compile without this:

```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**offscreen.html** script order:

```html
<script src="libs/tesseract.min.js"></script>
<script src="libs/face-api.min.js"></script>
<script src="delta.js"></script>
<script src="offscreen.hardening.js"></script>
<script src="offscreen.js"></script>
```

---

## 1. Delta encoding — `extension/delta.js`

Tile the **veiled, pre-mark** canvas at 64px, FNV-1a each tile over a 2x-subsampled, 5-bit-quantised sample, diff against the previous grid, dilate by one tile, merge runs into rects.

Hashing pre-mark matters: it means renumbering a chip never registers as motion, so "did my click do anything?" stays a clean signal.

Three wire modes:

- **`unchanged`** — zero image bytes, and the server sends the model zero image tokens.
- **`patch`** — one crop of the dirty union box plus its origin.
- **`full`** — keyframe. Forced on geometry change, on URL change, every 8 steps, or when change ratio > 30%.

**Prerequisite, and it is not optional:** stable mark IDs. If `[14]` means a different element after a DOM insert, a patch referring to `[14]` is silently wrong. `AAVARAN_BG.StableMarkIds` content-addresses each mark on `role|name|editable|bbox/16`, so identity survives reflow.

### Patch into `offscreen.js`

Right after `const pixelHash = perceptualHash(...)` (§6, before marks are drawn):

```js
/* ---- delta grid: computed on veiled, PRE-MARK pixels ------------------ */
const grid = AAVARAN_DELTA.tileGrid(egressCanvas);
const diff = AAVARAN_DELTA.diffGrid(payload.prevGrid || null, grid);
const plan = AAVARAN_DELTA.choose(diff, grid, {
  forceFull: !!payload.forceKeyframe,
  stepsSinceKeyframe: payload.stepsSinceKeyframe || 0,
});

let patchDataUrl = null;
if (plan.mode === 'patch') {
  const [px, py, pw, ph] = plan.rect;
  const { canvas: pc, ctx: pctx } = makeCanvas(pw, ph);
  pctx.drawImage(egressCanvas, px, py, pw, ph, 0, 0, pw, ph);
  // marks must be drawn INTO the patch, at patch-local coordinates
  drawMarks(pctx, marks
    .filter((m) => boxIntersect(m.bbox, [px, py, px + pw, py + ph]))
    .map((m) => ({ ...m, bbox: [m.bbox[0]-px, m.bbox[1]-py, m.bbox[2]-px, m.bbox[3]-py] })),
    { width: pw, height: ph, fontSize: markFontSize, lineWidth: markLineWidth });
  patchDataUrl = await blobToDataUrl(await canvasToBlob(pc));
}
```

Return alongside the existing payload:

```js
frameDelta: {
  mode: plan.mode,
  reason: plan.reason,
  rect: plan.rect || null,
  changeRatio: diff.ratio,
  width: grid.width,
  height: grid.height,
  frameId: crypto.randomUUID(),
},
grid,                       // background.js stores this as next step's prevGrid
patchDataUrl,
```

`background.js` then sends `image = patchDataUrl` when mode is `patch`, `null` when `unchanged`, the full egress PNG otherwise.

---

## 2. Fail-closed privacy — `extension/offscreen.hardening.js`

Three recall profiles, auto-selected by host (`SENSITIVE_HOST_RE` covers Indian banking, UPI, UIDAI, `gov.in`):

| | `balanced` | `strict` (default) | `paranoid` (sensitive hosts) |
|---|---|---|---|
| OCR confidence floor | 55 | 70 | 82 |
| face score threshold | 0.40 | 0.25 | 0.15 |
| min digit run | 4 | 3 | 2 |
| opaque fallback | off | on | on |

Raising the confidence floor *increases* redaction: words below the floor are treated as unreadable, and unreadable-and-numeric fails closed.

Three new recall bands on top of your existing span rules:

1. **Low-confidence numeric** — you have this; the profile just calibrates the threshold per host.
2. **Label proximity** — `LABEL_RE` matches ~30 label forms (`A/c No`, `Aadhaar`, `IFSC`, `Valid Thru`, `Available Bal`, `CIF`, …). Everything to the right of a label on the same OCR line is redacted, even when the value itself parsed as nothing. This is the highest-yield rule on Indian banking UIs, where the value is a webfont Tesseract mangles while the label is plain system text.
3. **Masked forms** — `XXXX XXXX 4291`, `•••• 1234`. These are invisible to every checksum rule you have, because they aren't valid numbers.

**The one that would have saved today's run:** `opaqueFallbackBoxes()`. When face detection fails, "0 faces destroyed" is not a true statement — the truth is *unknown*. Under `strict`/`paranoid` a face-model failure redacts every `img`/`video`/`canvas`/`figure` region larger than 48x48px instead of shipping the frame clean. Your panel currently reads `faces destroyed 0` next to `face_detection_failed`, and sends the frame anyway.

### Patch into `offscreen.js`

Replace the body of `assertLocalAssets()` with a call to `AAVARAN_HARDEN.assertLocalAssets()` (it now checks `tesseract-core.wasm` too, runs the fetches in parallel, and prints the exact URL to re-fetch for each failure).

In §6.4, after the `for (const span of spans)` loop:

```js
const profile = AAVARAN_HARDEN.profileFor(payload.viewport?.url || payload.url, cfg.recallProfile);
const claimedIdx = new Set();
for (const span of spans) for (const i of wordsInSpan(map, span.start, span.end)) claimedIdx.add(i);

const fc = AAVARAN_HARDEN.failClosedBoxes(
  ocrWords, cfg, profile, ocrScale, devW, devH, normBox, claimedIdx,
);
redactions.push(...fc.boxes);
failClosedRegions = fc.boxes.length;
```

In §6.3, in the face `catch` block:

```js
} catch (e) {
  warn('face detection failed:', e);
  warnings.push(`face_detection_failed: ${e.message}`);
  if (profile.opaqueFallback) {
    const fb = AAVARAN_HARDEN.opaqueFallbackBoxes(payload, cssToDev, normBox, cfg, devW, devH);
    redactions.push(...fb);
    warnings.push(`face_fallback: ${fb.length} opaque regions destroyed on suspicion`);
  }
}
```

And pass `profile.faceScore` into `TinyFaceDetectorOptions` instead of the hardcoded `0.4`.

---

## 3. Async handshaking — `extension/background.hardening.js`

Five distinct sources of your cold-start lag, each fixed separately.

**Creation race.** `ensureOffscreen()` is single-flight. Two concurrent captures used to race `createDocument` and the loser threw *"Only a single offscreen document may be created"*, surfacing as a spurious veil failure on step 1.

**Readiness race.** `createDocument()` resolving does not mean the document's scripts have executed. `waitForOffscreenReady()` does a real `AAVARAN_PING` / ack with exponential backoff (25ms → 400ms, 8s ceiling) instead of a fixed `setTimeout`. Add this to `offscreen.js`:

```js
if (msg.type === 'AAVARAN_PING') { sendResponse({ ok: true, warm: AAVARAN_HARDEN.warmState() }); return true; }
if (msg.type === 'AAVARAN_WARMUP') {
  AAVARAN_HARDEN.warmup(initOcr, initFaces, msg.payload).then(sendResponse);
  return true;
}
```

**Serial init.** `warmup()` runs `initOcr` and `initFaces` under `Promise.all` of catch-wrapped promises. That overlaps ~1.2s of wasm compile with ~0.6s of shader compile, and one failing no longer prevents the other — which is exactly your current state, where broken Tesseract assets also cost you face redaction.

**Service worker death.** MV3 evicts an idle SW at 30s and takes the offscreen document with it, so step 12 pays a full cold start. `beginRun()` / `endRun()` hold a `chrome.alarms` keepalive only while a run is active. Call them around your run loop.

**Redundant OCR.** `ObservationCache` keys on a 32x32 SHA of the raw frame. On a pixel-identical recapture, OCR is skipped entirely — 2082ms → ~50ms. In a ReAct loop, failed clicks and hovers make this hit far more often than you'd guess. Wire it at the top of `veil()`:

```js
const key = await AAVARAN_HARDEN.frameKey(full, profile.name);
const cached = OBS_CACHE.get(key);
if (cached) { timings.cacheHit = true; return { ...cached, cached: true }; }
```

Warm triggers are already registered at the bottom of the module: `onStartup`, `onInstalled`, `action.onClicked`.

### One separate bug in your panel

Your trace shows the same five entries re-appended every 2 seconds with identical latencies (338 / 2082 / 341 / 1406ms). Those are not new veils. The panel is re-rendering its whole buffer on each poll instead of appending the tail. Keyed append or a `Set` on the trace entry ID fixes it — worth doing before the demo, because right now the trace is unreadable.

---

## 4. Action validation — `server/actions.py` + client mirror

The whitelist is **closed**, and it is enforced in both processes. The server is the thing talking to an untrusted model; the extension is the thing holding the user's cookies. Neither trusts the other.

14 actions: `click`, `double_click`, `type`, `clear`, `press_key`, `select_option`, `scroll`, `hover`, `navigate`, `go_back`, `wait`, `extract`, `ask_user`, `finish`.

Checks, in order:

- Unknown action type → rejected with the allowed list.
- **Unknown *field* → rejected, not ignored.** A model emitting `selector` or `xpath` has left the grounding contract. Silently dropping the field means executing something different from what it reasoned about.
- `index` must exist in *this frame's* manifest; the rejection names the valid indices.
- `type`/`clear` require `editable`; `select_option` requires a select role and, when options are known, a valid option.
- `press_key` against a 15-key whitelist. `scroll` bounded 0–5000, `wait` 0–15000ms.
- `navigate` http/https only (`javascript:`, `data:`, `file:` blocked), host allowlist.
- **Cross-origin PII is a hard stop.** Each vault token is bound to the origin it was captured on. A model proposing to type `<PII:CARD#1>` learned on the bank's origin into a form on another origin is describing exfiltration regardless of intent — that is rejected, not confirmed.
- Loop breaker: the same signature twice with `noop: true` is rejected with a hint to try something else.
- Destructive intent (`pay`, `transfer`, `delete`, `place order`, `authorise`…) on a state-changing action sets `requiresConfirmation` → the panel gates on a human.

`schema_text()` renders the whitelist into the system prompt from the same table the validator reads, so prompt and validator cannot drift. Prompt/validator drift is the largest avoidable source of repair loops.

Rejections don't abort the run. The offending output *and* the rejection reason both go into the transcript and the model retries (`MAX_REPAIRS=2`). Re-prompting without showing the model its own bad output roughly doubles the repair rate.

Validator test results:

```
PASS  click index=1                    -> accepted, risk=medium
PASS  click index=99                   -> bad_index
PASS  type into a button               -> not_editable
PASS  execute_script                   -> unknown_action
PASS  click + "selector": ".btn"       -> unknown_field
PASS  press_key F12                    -> bad_key
PASS  navigate javascript:alert(1)     -> bad_scheme
PASS  navigate https://evil.com        -> host_not_allowed
PASS  select_option value="2099"       -> bad_option
PASS  ```json-fenced click             -> accepted (fence stripped)
PASS  "index": true                    -> bad_type
PASS  click "Confirm and Pay"          -> accepted, requiresConfirmation=true
PASS  <PII:CARD#1> typed on other host -> cross_origin_pii
```

---

## 5. `server/main.py`

- `/act` takes the delta observation. `FrameStore` reconstructs an authoritative full frame server-side (so logging and glass-box replay always have a coherent screenshot) while framing for the VLM separately — those are different decisions and conflating them is why naive delta encoding saves bytes but no tokens.
- Sliding window over **images, not turns**. Old turns keep their text (cheap, load-bearing reasoning trace) and drop their images. `MAX_IMAGES=3`.
- `SYSTEM_PROMPT` is byte-stable for the whole run. Never interpolate the goal or step number into it or every request misses upstream prompt caching and you pay the full prefix 30 times.
- `/preflight` now exists. It failed in your logs because there was nothing on the other end, and the panel couldn't distinguish "server down" from "assets broken". It now reports server status, VLM reachability and the active policy separately.
- Per-session `asyncio.Lock` on `/act`. Without it, a double-click on Run interleaves two steps into one turn list.

Measured against your current setup, on a 20-step run at 1536px egress:

```
image tokens, always-full:   20 x 1,620  =  32,400
image tokens, delta policy:  3 x 1,620 + 17 x ~90  =  ~6,390     (-80%)
```

```bash
pip install fastapi uvicorn httpx pillow pydantic
export AAVARAN_VLM_BASE=http://127.0.0.1:8000/v1
export AAVARAN_VLM_MODEL=Qwen/Qwen2.5-VL-7B-Instruct
uvicorn main:app --host 127.0.0.1 --port 8756
```

---

## Order of operations

1. `fetch-libs.ps1 -Clean`, confirm the size table.
2. `manifest.json` CSP, `offscreen.html` script order.
3. Reload the extension, hit **Preflight**. You want `ocr` and `face` both true, `mode` no longer `wireframe`.
4. **Stop here and confirm OCR works before anything else.** Every one of the four optimisations is downstream of a working veil, and hardening a pipeline that can't see is how you spend demo day debugging the wrong layer.
5. Then: stable mark IDs → delta → fail-closed → warmup → validation.
