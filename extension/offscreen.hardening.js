'use strict';
/* ==========================================================================
 * AAVARAN — offscreen.hardening.js
 * ==========================================================================
 * Load in offscreen.html AFTER libs, BEFORE offscreen.js:
 *   <script src="libs/tesseract.min.js"></script>
 *   <script src="libs/face-api.min.js"></script>
 *   <script src="delta.js"></script>
 *   <script src="offscreen.hardening.js"></script>
 *   <script src="offscreen.js"></script>
 *
 * Exposes self.AAVARAN_HARDEN. Nothing here touches the network.
 * ========================================================================== */

(function (root) {
  const log = (...a) => console.log('[AAVARAN/harden]', ...a);
  const warn = (...a) => console.warn('[AAVARAN/harden]', ...a);

  /* ======================================================================
   * 1. Preflight — replaces assertLocalAssets() in offscreen.js
   * ====================================================================== */

  // tesseract-core.wasm.js is emscripten glue; it fetches tesseract-core.wasm
  // from its own directory at runtime. The old preflight checked the glue and
  // not the payload, so a half-populated libs/ could still pass.
  const REQUIRED_ASSETS = [
    ['libs/tesseract.min.js', 40_000, 'unpkg.com/tesseract.js@5.1.1/dist/tesseract.min.js'],
    ['libs/worker.min.js', 10_000, 'unpkg.com/tesseract.js@5.1.1/dist/worker.min.js'],
    ['libs/tesseract-core.wasm.js', 100_000, 'unpkg.com/tesseract.js-core@5.1.1/tesseract-core.wasm.js'],
    ['libs/tesseract-core.wasm', 2_000_000, 'unpkg.com/tesseract.js-core@5.1.1/tesseract-core.wasm'],
    ['libs/tessdata/eng.traineddata', 1_000_000, 'github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata'],
    ['libs/face-api.min.js', 100_000, 'unpkg.com/face-api.js@0.22.2/dist/face-api.min.js'],
    ['libs/models/tiny_face_detector_model-weights_manifest.json', 100,
      'raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/tiny_face_detector_model-weights_manifest.json'],
    ['libs/models/tiny_face_detector_model-shard1', 100_000,
      'raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/tiny_face_detector_model-shard1'],
  ];

  let preflightCache = null;

  async function assertLocalAssets(force) {
    if (preflightCache && !force) return preflightCache;
    const problems = [];
    const sizes = {};
    await Promise.all(REQUIRED_ASSETS.map(async ([rel, min, source]) => {
      try {
        const res = await fetch(chrome.runtime.getURL(rel));
        if (!res.ok) { problems.push({ rel, detail: `HTTP ${res.status}`, source }); return; }
        const buf = await res.arrayBuffer();
        sizes[rel] = buf.byteLength;
        if (buf.byteLength < min) {
          problems.push({ rel, detail: `${buf.byteLength} bytes, expected >= ${min}`, source });
        }
      } catch (e) {
        problems.push({ rel, detail: e.message, source });
      }
    }));
    preflightCache = { ok: problems.length === 0, problems, sizes };
    if (problems.length) {
      warn('ASSET PREFLIGHT FAILED:\n' + problems
        .map((p) => `  ${p.rel}\n    -> ${p.detail}\n    -> fetch from https://${p.source}`)
        .join('\n'));
    }
    return preflightCache;
  }

  /* ======================================================================
   * 2. Warmup — kills cold start (requirement 3, offscreen half)
   * ====================================================================== */

  const WARM = { state: 'cold', promise: null, detail: null };

  /**
   * initOcr and initFaces are independent: Tesseract spins a dedicated Worker
   * thread, face-api warms a WebGL context on the document thread. Running
   * them with allSettled overlaps ~1.2s of wasm compile with ~0.6s of shader
   * compile, and — critically — one failing no longer prevents the other from
   * being ready. The old sequential path meant a broken Tesseract also cost
   * you face redaction.
   */
  function warmup(initOcr, initFaces, opts) {
    if (WARM.promise) return WARM.promise;
    const cfg = opts || {};
    WARM.state = 'warming';
    WARM.promise = (async () => {
      const t0 = performance.now();
      const pre = await assertLocalAssets(true);
      const tasks = [];
      tasks.push(pre.ok && cfg.enableOcr !== false
        ? initOcr().then(() => ({ k: 'ocr', ok: true }), (e) => ({ k: 'ocr', ok: false, e: e.message }))
        : Promise.resolve({ k: 'ocr', ok: false, e: 'assets_missing' }));
      tasks.push(pre.ok && cfg.enableFaces !== false
        ? initFaces().then(() => ({ k: 'face', ok: true }), (e) => ({ k: 'face', ok: false, e: e.message }))
        : Promise.resolve({ k: 'face', ok: false, e: 'assets_missing' }));

      const results = await Promise.all(tasks);
      const detail = {
        ok: pre.ok,
        ms: Math.round(performance.now() - t0),
        ocr: results.find((r) => r.k === 'ocr').ok,
        face: results.find((r) => r.k === 'face').ok,
        problems: pre.problems.map((p) => `${p.rel}: ${p.detail}`),
        errors: results.filter((r) => !r.ok && r.e).map((r) => `${r.k}: ${r.e}`),
        sizes: pre.sizes,
      };
      WARM.state = detail.ocr || detail.face ? 'warm' : 'failed';
      WARM.detail = detail;
      log('warmup', WARM.state, detail);
      return detail;
    })();
    return WARM.promise;
  }

  function warmState() { return { state: WARM.state, detail: WARM.detail }; }

  /* ======================================================================
   * 3. Fail-closed recall (requirement 2)
   * ====================================================================== */

  // A value the OCR could not parse is still PII if the page told us what it
  // is. Label proximity is the highest-yield recall rule in Indian banking
  // and KYC UIs, where the value is often rendered in a webfont Tesseract
  // struggles with while the label is plain system text.
  const LABEL_RE = new RegExp([
    'aadha?ar', 'uidai', 'pan\\s*(no|number|card)?', 'gstin?', 'ifsc',
    'a\\/?c\\s*(no|number)?', 'acc(ou)?nt\\s*(no|number)?', 'card\\s*(no|number)?',
    'cvv', 'expiry', 'valid\\s*thru', 'upi\\s*(id)?', 'vpa',
    'mobile', 'phone', 'contact\\s*(no|number)?',
    'dob', 'date\\s*of\\s*birth', 'passport',
    'balance', 'available\\s*bal', 'closing\\s*bal', 'amount',
    'otp', 'pin', 'password', 'customer\\s*id', 'cif', 'folio',
    'salary', 'income', 'nominee',
  ].join('|'), 'i');

  // Values already partially masked by the site. These are the ones a naive
  // regex set misses completely, because they are not valid numbers.
  const MASKED_RE = /(?:[xX*•●]\s*){3,}[\s-]*\d{2,}|\d{2,}[\s-]*(?:[xX*•●]\s*){3,}/;

  const RECALL_PROFILES = Object.freeze({
    // For public pages. Roughly the original behaviour.
    balanced: { ocrConfFloor: 55, faceScore: 0.40, minDigitRun: 4, labelLine: true, maskedForms: true, opaqueFallback: false },
    // Default. Fails toward redaction on anything ambiguous.
    strict: { ocrConfFloor: 70, faceScore: 0.25, minDigitRun: 3, labelLine: true, maskedForms: true, opaqueFallback: true },
    // Banking / gov / any origin on the sensitive list.
    paranoid: { ocrConfFloor: 82, faceScore: 0.15, minDigitRun: 2, labelLine: true, maskedForms: true, opaqueFallback: true },
  });

  const SENSITIVE_HOST_RE = /(bank|netbanking|onlinesbi|icici|hdfc|axis|kotak|paytm|phonepe|gpay|razorpay|npci|uidai|incometax|gov\.in|nic\.in|epfindia|nsdl|cdsl|insurance|policybazaar)/i;

  function profileFor(url, override) {
    if (override && RECALL_PROFILES[override]) return { name: override, ...RECALL_PROFILES[override] };
    let host = '';
    try { host = new URL(url).hostname; } catch { /* about:blank etc */ }
    if (SENSITIVE_HOST_RE.test(host)) return { name: 'paranoid', ...RECALL_PROFILES.paranoid };
    return { name: 'strict', ...RECALL_PROFILES.strict };
  }

  /**
   * Extra redaction boxes from words the pattern rules did not claim.
   * Call AFTER the normal span loop, with the same words/map/scale.
   *
   * Three bands, each of which is a real miss in the current pipeline:
   *   a) low-confidence numeric   — garbled Aadhaar, the case the checksum
   *                                 cannot rescue and the one that matters
   *   b) label-proximate line     — "A/c No" recognised, value was not
   *   c) masked forms             — XXXX XXXX 4291
   *
   * @returns {{boxes:number[][], reasons:string[]}}
   */
  function failClosedBoxes(words, cfg, profile, scale, devW, devH, normBox, claimedWordIdx) {
    const boxes = [];
    const reasons = [];
    const claimed = claimedWordIdx || new Set();

    const push = (w, why) => {
      boxes.push(normBox(
        w.bbox.x0 / scale, w.bbox.y0 / scale,
        w.bbox.x1 / scale, w.bbox.y1 / scale,
        cfg.redactionPad, devW, devH,
      ));
      reasons.push(why);
    };

    // Group by OCR line so label proximity can sweep a whole row.
    const byLine = new Map();
    words.forEach((w, i) => {
      if (!byLine.has(w.line)) byLine.set(w.line, []);
      byLine.get(w.line).push({ w, i });
    });

    for (const [, entries] of byLine) {
      const lineText = entries.map((e) => e.w.text).join(' ');
      const labelHit = profile.labelLine ? LABEL_RE.exec(lineText) : null;
      // Everything to the right of the label on the same line is the value.
      const labelEnd = labelHit ? labelHit.index + labelHit[0].length : -1;
      let cursor = 0;

      for (const { w, i } of entries) {
        const start = cursor;
        cursor += w.text.length + 1;
        if (claimed.has(i)) continue;

        const digits = w.text.replace(/\D/g, '');

        if (w.confidence < profile.ocrConfFloor && digits.length >= profile.minDigitRun) {
          push(w, `low_conf_numeric(${Math.round(w.confidence)})`);
          continue;
        }
        if (profile.maskedForms && MASKED_RE.test(w.text)) {
          push(w, 'masked_form');
          continue;
        }
        if (labelHit && start >= labelEnd && (digits.length >= profile.minDigitRun || /[@]/.test(w.text))) {
          push(w, `label_proximity(${labelHit[0].trim()})`);
          continue;
        }
        // A word the OCR is genuinely unsure about, sitting on a labelled
        // line, is redacted regardless of shape. We cannot know what we
        // cannot read, so we refuse to transmit it.
        if (labelHit && start >= labelEnd && w.confidence < profile.ocrConfFloor) {
          push(w, 'unreadable_on_labelled_line');
        }
      }
    }
    return { boxes, reasons };
  }

  /**
   * When the face model is unavailable, "0 faces redacted" is a lie — the
   * correct statement is "unknown". Redact every DOM region that could carry
   * a face: img, video, canvas, svg avatars, and anything the content script
   * flagged opaque. Today's logs show face_detection_failed with 0 faces
   * destroyed and a frame still going out. That is the exact failure this
   * closes.
   */
  function opaqueFallbackBoxes(payload, cssToDev, normBox, cfg, devW, devH) {
    const out = [];
    const candidates = [
      ...(Array.isArray(payload.opaque) ? payload.opaque : []),
      ...(Array.isArray(payload.domMarks) ? payload.domMarks : [])
        .filter((m) => /^(img|image|video|canvas|figure|avatar)$/i.test(m.role || '')),
    ];
    for (const r of candidates) {
      const rect = r.rect || r.bbox || r;
      if (typeof rect.x !== 'number') continue;
      // Skip icon-sized elements: a 16px sprite is not a face and blacking
      // out every icon destroys the page's affordances for the VLM.
      if (rect.w < 48 || rect.h < 48) continue;
      out.push(normBox(...cssToDev(rect), cfg.redactionPad, devW, devH));
    }
    return out;
  }

  /* ======================================================================
   * 4. Observation cache — the other half of the cold-start fix
   * ====================================================================== */

  /**
   * OCR is 80-95% of veil latency (your trace: 2082ms). In a ReAct loop the
   * page is frequently pixel-identical to the previous step — a failed click,
   * a hover, a re-capture after a no-op. Re-running Tesseract on identical
   * pixels is pure waste.
   *
   * Keyed on a cheap hash of the RAW frame, so it short-circuits before any
   * model runs. Bounded, because the entries hold redaction geometry derived
   * from plaintext and must not outlive the session.
   */
  class ObservationCache {
    constructor(max = 12) { this.max = max; this.map = new Map(); }

    get(key) {
      if (!this.map.has(key)) return null;
      const v = this.map.get(key);
      this.map.delete(key);
      this.map.set(key, v);           // LRU touch
      return v;
    }

    set(key, value) {
      if (this.map.has(key)) this.map.delete(key);
      this.map.set(key, value);
      while (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
    }

    clear() { this.map.clear(); }
  }

  /** Fast content hash of a canvas, used only as a cache key. */
  async function frameKey(canvas, extra) {
    const { canvas: small } = (() => {
      const c = new OffscreenCanvas(32, 32);
      const x = c.getContext('2d', { willReadFrequently: true });
      x.drawImage(canvas, 0, 0, 32, 32);
      return { canvas: c };
    })();
    const px = small.getContext('2d').getImageData(0, 0, 32, 32).data;
    const digest = await crypto.subtle.digest('SHA-256', px);
    const hex = [...new Uint8Array(digest)].slice(0, 12)
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex}|${extra || ''}`;
  }

  root.AAVARAN_HARDEN = {
    REQUIRED_ASSETS,
    assertLocalAssets,
    warmup,
    warmState,
    RECALL_PROFILES,
    profileFor,
    failClosedBoxes,
    opaqueFallbackBoxes,
    ObservationCache,
    frameKey,
    LABEL_RE,
    MASKED_RE,
  };
}(self));
