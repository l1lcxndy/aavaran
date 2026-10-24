# AAVARAN

**A browser agent that can act on a page it is not allowed to see.**

आवरण — *āvaraṇa*, Sanskrit: a veil, a covering, that which conceals.

---

## 1. The problem

Every vision-based browser agent works the same way: screenshot the page, send
the pixels to a vision-language model, get back an action. That screenshot
contains whatever was on screen — your Aadhaar number, your account balance,
your face, the OTP that just arrived.

For an Indian user on a banking or KYC page, using a browser agent currently
means transmitting your complete financial identity to a third-party inference
endpoint, on every single step of the task, as a side effect of asking it to
download a statement.

The usual answers are all bad. Run the model locally — you lose the capability
that made it worth using. Blur the sensitive regions — a blur is a reversible
transform and the pixels are still in the file. Ask the model nicely not to
look — it is a model.

## 2. What AAVARAN does

It puts a veil between the browser and the model.

Pixels are **destroyed**, not obscured, before the frame is encoded. Interactive
elements are replaced with numbered boxes, so the model acts by citing an index
rather than by reading the page. Redacted values are replaced with **opaque
tokens** the model can reference but never read — it can type your card number
into a form without the number ever existing in its context.

The model gets enough to act. It does not get enough to identify you.

```
┌─ YOUR MACHINE ─────────────────────────────────────────────────┐
│                                                                │
│  page ──► captureVisibleTab ──► raw frame (never leaves)       │
│                                      │                         │
│                          ┌───────────┼───────────┐             │
│                          ▼           ▼           ▼             │
│                     face-api    Tesseract    DOM channel       │
│                     (local)      (local)     (passwords,       │
│                          │           │        input values)    │
│                          └───────────┼───────────┘             │
│                                      ▼                         │
│                            redaction geometry                  │
│                                      ▼                         │
│                      ╔═══════════════════════════╗             │
│                      ║  DESTRUCTIVE FILL         ║             │
│                      ║  pixels cease to exist    ║             │
│                      ╚═══════════════════════════╝             │
│                                      ▼                         │
│                         perceptual hash + tile grid            │
│                                      ▼                         │
│                         downscale to egress res                │
│                                      ▼                         │
│                         Set-of-Mark overlay [1][2][3]          │
│                                      ▼                         │
│                         PNG encode                             │
│                                      ▼                         │
│                      ╔═══════════════════════════╗             │
│                      ║  EGRESS VERIFICATION      ║             │
│                      ║  re-OCR the actual bytes  ║             │
│                      ╚═══════════════════════════╝             │
│                                      │                         │
│   TOKEN VAULT (plaintext, memory only, origin-bound) ──X       │
└──────────────────────────────────────┼─────────────────────────┘
                                       ▼
                        ┌──────────────────────────┐
                        │  main.py                 │
                        │  frame reconstruction    │
                        │  ACTION WHITELIST  ◄─── every proposal
                        │  self-repair loop        │
                        └──────────┬───────────────┘
                                   ▼
                            Qwen2.5-VL
```

---

## 3. The five ideas

### 3.1 Destructive redaction

The pixels are overwritten with opaque fill on the full-resolution canvas,
*before* downscale and *before* encode. There is no layer to peel back, no CSS
overlay to remove, no lower-frequency residue to recover. The information is
not hidden in the transmitted file; it is absent from it.

### 3.2 Set-of-Mark grounding

Interactive elements get numbered boxes drawn over them. The model answers
`{"type":"click","index":14}` — never a pixel coordinate.

This is not a cosmetic choice. Coordinate-predicting agents fail constantly
because a model's spatial estimate lands 20–40px off target on a non-default
display scale. An index either exists in the manifest or it does not, which
makes the grounding contract **verifiable**: an invalid index is caught before
anything is clicked, rather than producing a click on whatever happened to be
at those coordinates.

Label chips are placed by collision search, because an occluded label is an
unreadable index, and an unreadable index is an action the model cannot
express.

### 3.3 Tokenised PII

A detected Aadhaar becomes `<PII:AADHAAR#1>`. The token is deterministic —
derived from `SHA-256(kind|value)` — so the same value carries the same token
at step 1 and step 17, even though the offscreen document may have been torn
down and rebuilt in between.

The model can compose actions referencing the token. The extension resolves it
at execution time, locally. **The plaintext never enters the model's context
window**, so it cannot be memorised, logged by the inference provider, or
leaked through the model's own output.

Each token is bound to the origin it was captured on. A proposal to type
`<PII:CARD#1>` — learned on the bank's origin — into a form on a different
origin is rejected outright, not confirmed. That is an exfiltration pattern
regardless of whether the model "intended" it.

### 3.4 Checksum-gated detection, with a fail-closed floor

Aadhaar validates against the **Verhoeff** algorithm — a dihedral-group
checksum over D₅, chosen by UIDAI specifically because, unlike a simple
mod-10 sum, it catches all single-digit errors *and* all adjacent
transpositions. Cards validate against **Luhn**.

Validation gives precision. But a redaction pipeline's objective is recall: a
false redaction costs one retry, a miss costs an identity. So beneath the
validating rules sits a fail-closed floor that redacts anything *shaped* like
an identifier whether or not it checksums — grouped digit runs, masked forms
(`XXXX XXXX 4291`), low-confidence OCR words containing digits, and anything
sitting to the right of a label like `A/c No` or `Aadhaar`.

> **Found during integration:** the original rule set transmitted
> `1234 5678 9012` completely unredacted. It starts with 1, which UIDAI
> reserves, so the Aadhaar regex never matched; it is 12 digits, so the card
> rule (13+) never matched; the spaces split it into three 4-digit runs, so
> the 9+ digit account rule never matched. Three independent rules, three
> misses, one identity in the clear. This is precisely why the floor exists.

### 3.5 Delta encoding

A ReAct loop re-sends a near-identical screenshot every step, of which
typically 2–6% is new. The veiled, pre-mark canvas is tiled at 64px and
hashed; unchanged tiles are not retransmitted.

Hashing happens *pre-mark* deliberately: renumbering a chip must never look
like a state change, or the agent's "did my click do anything?" signal becomes
noise.

Three modes — `unchanged` (zero bytes, zero image tokens), `patch` (the dirty
region only), `full` (keyframe, forced on URL change and every 8 steps).

| | always-full | delta policy |
|---|---|---|
| 20-step run, 1536px egress | 32,400 image tokens | ~6,390 |

---

## 4. Current status

### Working and verified

| Component | Evidence |
|---|---|
| Veil pipeline in real Chromium (Tesseract + face-api + NER + rules) | `bench/veil_harness.html`, 200 rendered pages, numbers below |
| On-device NER (Transformers.js + ONNX Runtime Web, int8, 9.7 MB) | runs on WASM-SIMD; WebGPU is probed and rejected when its output is wrong (int8 on the WebGPU EP returns noise — measured) |
| PII rules + Verhoeff/Luhn, fail-closed bands | `node bench/run_rules.js` → recall 1.0 on the 200-page text channel |
| Server: signing, schema-constrained decoding, no-op adjudication, veil check, Redis store, Postgres audit | `cd server && python -m pytest -q` → 12 passed |
| Firefox build | `node scripts/build-firefox.js`, `web-ext lint` → 0 errors |

### Measured (bench/veil_harness.html, OCR channel, 1280×720 synthetic forms)

| Metric (deck target) | Measured | Notes |
|---|---|---|
| PII recall (≥ 0.95) | **0.985** (1,076 / 1,092 fields) | NAME 0.94, PAN 0.97, UPI 0.98, AADHAAR / PHONE / EMAIL / IFSC 1.00 |
| Precision | 0.997 (3 spurious of 1,039 boxes) | |
| Mask IoU (≥ 0.92) | **0.98** detector geometry (`?pad=0`); 0.63 as shipped | the shipped 4 px safety dilation is scored against glyph-tight truth |
| Veil latency per frame | median 335 ms, **p95 452 ms** | OCR 283 ms, faces 43 ms, NER 6 ms (WASM-SIMD) |
| Delta egress | one-word change: 3,966 B patch vs 26,006 B frame | patch pasted server-side reproduces the frame pixel-exactly |

**Local model** (`start.ps1 -Local`, Qwen2.5-VL 7B Q4 via Ollama, RTX 5060 Laptop 8 GB):

| | stock `qwen2.5vl:7b` | `aavaran-qwen` (same weights, vision input capped) |
|---|---|---|
| placement | 100% CPU (0/29 layers on GPU) | **100% GPU** (29/29) |
| vision scratch memory | 6.7 GiB | 758 MiB |
| cold load / step with a new 1024 px frame | ~170 s / ~42 s | **10.5 s / 2.3–3.4 s** (whole /act round trip) |

Ollama sizes the vision encoder's memory for `vision.max_pixels`, which the
model file omits (default ≈ 2 MP); `scripts/make-local-model.py` writes it as
1024×640. On the synthetic page at 1024 px: token fill 5/5 (3 after one
automatic repair — the validator rejects invented identifiers such as
`123456789012`), "pay the bill" → Confirm and Pay 2/2 and flagged for
confirmation. 1536 px frames scored worse, so egress now defaults to 1024 px.

Remaining misses are OCR errors the rules cannot see through (`B`→`8` in a
PAN, a UPI handle split into two words) and names NER scores below its floor.

Names on "Prepared for …" rows carry no label, so only the NER model can
catch them. Latency in the harness is inflated whenever the browser throttles
the tab, so read the per-stage `timings` (OCR is the dominant cost).

### Known gaps

1. **The real-model runs are synthetic.** Qwen2.5-VL 7B runs on the laptop GPU
   (below), measured on a synthetic bank page through the full server; a full
   multi-step task on a live site has not been scored.
2. **English OCR only** (`eng.traineddata`). Devanagari/Tamil/Bengali PII is
   invisible to the text channel.
3. **Model choices differ from the idea deck.** OCR is Tesseract (not
   PP-OCRv4) and faces are face-api's tinyFaceDetector (not YOLOv8n-face):
   both work and are measured; swapping needs a labelled face set to justify
   it. No screen-state ViT is used — no pretrained model exists for that
   task and the deck rules out training from scratch.
4. **Face recall is unmeasured** — there is no labelled face set in `bench/`.
5. **No formal privacy guarantee.** Redaction is checked against our own
   detectors; a stronger OCR or a human might recover more.
6. **Extension not exercised in a real Chrome/Firefox profile by tests.** The
   veil engine is (harness); the service worker / content-injection paths are
   syntax- and lint-checked only.

---

## 5. File map

```
aavaran/
├── fetch-libs.ps1                vendored browser libs + models, pinned (run once)
├── package.json                  npm scripts: fetch-libs, build:firefox, bench, test
├── docker-compose.yml            server + mock VLM + Redis + Postgres
├── scripts/build-firefox.js      Firefox variant → dist/firefox
│
├── extension/
│   ├── manifest.json
│   ├── background.js             orchestrator: vault (AES-GCM), egress guard, ReAct loop
│   ├── background.hardening.js   client-side action validation (imported by background.js)
│   ├── background.firefox.html   Firefox background page (no offscreen documents there)
│   ├── offscreen.html / .js      the veil engine: OCR, faces, NER, rules, SoM, delta
│   ├── offscreen.hardening.js    recall profiles, fail-closed bands, opaque fallback
│   ├── pii.hardening.js          unvalidated identifier shapes
│   ├── delta.js                  tile hashing, delta policy, stable mark ids
│   ├── panel/                    the Glass Box popup (+ narrator)
│   └── libs/                     tesseract, face-api, transformers.js, models
│
├── server/
│   ├── main.py                   /session, /act: validation, repair, signing
│   ├── actions.py                action whitelist + JSON Schema for constrained decoding
│   ├── framestore.py             delta reconstruction + VLM framing
│   ├── store.py                  sessions (memory/Redis), audit (JSONL/Postgres)
│   ├── veil_check.py             refuses observations with raw PII in text
│   ├── mock_vlm.py               scripted VLM stand-in
│   └── test_server.py            pytest suite
│
├── bench/
│   ├── generate.py               200 synthetic pages + labels
│   ├── run_rules.js              text-channel recall
│   ├── veil_harness.html/.js     full pipeline in a real browser
│   └── score.py                  recall / precision / IoU / p95
│
└── demo/                         deterministic PII fixture page
```

---

## 6. Setup from clean

**Quick start:** double-click `start.cmd` (or `.\start.ps1`; `.\start.ps1 -Local`
runs Qwen2.5-VL 7B on this machine through Ollama). It creates the venv and
fetches libs on first run, opens the model, server and page-server windows,
skips anything already running, and opens the demo page. Then load or reload
`extension\` in Chrome. The steps below are the same thing by hand.

```powershell
# 1. vendored libs + models (~48 MB, one time; NER assets are optional)
powershell -ExecutionPolicy Bypass -File .\fetch-libs.ps1 -Clean

# 2. server deps
python -m venv .venv; .\.venv\Scripts\pip install -r server\requirements-dev.txt
```

**3. Server** — two processes, two ports (the default `AAVARAN_VLM_BASE` is
`127.0.0.1:8000`; do not run the brain there or it calls itself):

```powershell
cd server
python -m uvicorn mock_vlm:app --host 127.0.0.1 --port 8001          # or a real vLLM
$env:AAVARAN_VLM_BASE = "http://127.0.0.1:8001/v1"
python -m uvicorn main:app --host 127.0.0.1 --port 8756
```

Or everything (server, mock VLM, Redis sessions, Postgres audit) with
`docker compose up --build`. Point `AAVARAN_VLM_BASE` at vLLM serving
Qwen2.5-VL-7B-Instruct to use a real model; actions are then grammar-
constrained via `response_format: json_schema` (XGrammar backend).

**4. Load the extension** — Chrome: `chrome://extensions` → Developer mode →
Load unpacked → `extension/`. Firefox 128+: `node scripts/build-firefox.js`,
then about:debugging → Load Temporary Add-on → `dist/firefox/manifest.json`,
and grant the site permission (Firefox makes host permissions opt-in).

**5. Preflight** — ocr / face / server dots green before anything else.

**Tests and benchmarks**

```powershell
cd server; python -m pytest -q; cd ..          # server suite
npm run bench                                   # text channel, 200 pages
python -m http.server 8770                      # then open:
#   http://127.0.0.1:8770/bench/veil_harness.html?n=200   (full veil in the browser)
```

---

## 7. Validator coverage

```
click index=1                     accepted, risk=medium
click index=99                    bad_index
type into a button                not_editable
execute_script                    unknown_action
click + "selector": ".btn"        unknown_field
press_key F12                     bad_key
navigate javascript:alert(1)      bad_scheme
navigate https://evil.com         host_not_allowed
select_option value="2099"        bad_option
```json-fenced click              accepted (fence stripped)
"index": true                     bad_type
click "Confirm and Pay"           accepted, requiresConfirmation=true
<PII:CARD#1> on foreign origin    cross_origin_pii
same action 3x with no change     repeated_noop
```

---

## 8. Troubleshooting — every failure hit during build

| Symptom | Cause | Fix |
|---|---|---|
| `worker.min.js: 0 bytes` | file lives at `tesseract.js@5/**dist**/`, was never downloaded | `fetch-libs.ps1` |
| `tesseract-core.wasm.js: 0 bytes` | lives in a **different npm package**, `tesseract.js-core` | `fetch-libs.ps1` |
| files created with 0 bytes | in PowerShell `curl` aliases `Invoke-WebRequest`; `-L`/`-o` don't parse | use the script |
| `face_detection_failed: Failed to fetch` | `tinyFaceDetector` has one shard; downloading `shard2` saved a 404 page | `fetch-libs.ps1` |
| wasm won't compile, no clear error | missing `'wasm-unsafe-eval'` in CSP | §6 step 2 |
| `preflight server 404` | extension polls `/healthz`, server only had `/health` | alias added in `main.py` |
| `Error loading ASGI app: "main"` | uvicorn run from the wrong cwd | `cd server` first |
| server calls itself as the VLM | brain and default `VLM_BASE` both on :8000 | separate ports, §6 step 5 |
| trace repeats every 2s | panel re-rendered its whole buffer per poll | `panel.js` id dedup |
| Aadhaar transmitted in the clear | three rules, three independent misses | `pii.hardening.js` |
| `faces destroyed 0` next to a face failure | "0" and "unknown" conflated | `opaqueFallbackBoxes()` |
| `on_event is deprecated` | FastAPI lifespan API changed | cosmetic, ignore |

---

## 9. Configuration

**Server** (env vars)

| var | default | meaning |
|---|---|---|
| `AAVARAN_VLM_BASE` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint |
| `AAVARAN_VLM_MODEL` | `Qwen/Qwen2.5-VL-7B-Instruct` | model id |
| `AAVARAN_MAX_REPAIRS` | `2` | validator retries before giving up |
| `AAVARAN_MAX_IMAGES` | `3` | images kept in context |
| `AAVARAN_KEYFRAME_EVERY` | `8` | forced full-frame interval |

**Veil** (`DEFAULTS` in `offscreen.js`)

| key | default | meaning |
|---|---|---|
| `egressMaxEdge` | 1536 | long edge of the transmitted frame |
| `ocrMaxEdge` | 3000 | OCR resolution (accuracy is resolution-bound) |
| `ocrConfFloor` | 55 → 70 → 82 | *raising this increases redaction* |
| `redactionPad` | 4 | dilation, device px |
| `maxMarks` | 120 | beyond this a VLM cannot disambiguate |
| `failMode` | `wireframe` | on OCR failure: schematic frame, or refuse |

**Recall profiles** — auto-selected by host

| | `balanced` | `strict` (default) | `paranoid` (banks, `gov.in`) |
|---|---|---|---|
| OCR confidence floor | 55 | 70 | 82 |
| face score threshold | 0.40 | 0.25 | 0.15 |
| min digit run | 4 | 3 | 2 |
| opaque fallback | off | on | on |

---

## 10. Honest limits

- Egress verification tests the artifact against *our own* OCR pipeline. It
  closes the class of bug where geometry is computed right and applied wrong —
  which is the class that actually ships — but it is not a proof of privacy.
- Recall on the text channel is bounded by Tesseract. Stylised webfonts,
  low contrast, and non-Latin scripts all degrade it, and the fail-closed
  floor is a mitigation, not a solution.
- The system does not defend against a malicious *server*. It limits what the
  server receives; it assumes the extension itself is trustworthy.
- "DPDP-aligned" describes design intent — data minimisation, purpose
  limitation, local processing. It is **not** a legal compliance
  certification, and nobody on this project is a lawyer. Say it that way.
