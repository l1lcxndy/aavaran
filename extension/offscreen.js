'use strict';

const DEFAULTS = Object.freeze({
  // Transmitted long edge. On local Qwen2.5-VL 7B, 1024 beat 1536 (9/9 vs 3/6) at ~60% of the image tokens.
  egressMaxEdge: 1024,
  // Long edge used for OCR. OCR accuracy is resolution-bound, so this stays
  // near native. Above ~3000px Tesseract cost grows faster than its recall.
  ocrMaxEdge: 3000,
  // OCR scale cap relative to CSS px. A DPR-2 capture is downscaled to 1.5x
  // CSS, so 13-14 px body text still reaches Tesseract ~20 px tall (more than
  // a DPR-1 screen ever gives it) at ~half the pixels of the native grab.
  ocrCssScale: 1.5,
  // Long edge for face detection. tinyFaceDetector internally resizes to 416.
  faceMaxEdge: 2048,
  // Words below this Tesseract confidence are treated as unreadable. Anything
  // unreadable that looks even vaguely numeric is redacted anyway: fail closed.
  ocrConfFloor: 55,
  // Redaction boxes are dilated by this many device px on every side. OCR
  // bounding boxes clip ascenders and descenders; a tight box leaves slivers.
  redactionPad: 4,
  // Marks beyond this count are dropped (lowest-priority first). A VLM cannot
  // meaningfully disambiguate 300 numbered boxes, and the label layer becomes
  // visual noise that degrades grounding accuracy.
  maxMarks: 120,
  // 'wireframe' → on OCR failure, synthesise a zero-pixel schematic frame.
  // 'block'     → on OCR failure, refuse to produce an egress frame at all.
  failMode: 'wireframe',
  enableFaces: true,
  enableOcr: true,
  // Draw the assigned token (<PII:AADHAAR#1>) onto the redaction bar. This is
  // what lets the VLM *reference* redacted data it can never read.
  labelRedactions: true,
  kinds: {
    AADHAAR: true, PAN: true, PHONE: true, EMAIL: true, UPI: true,
    IFSC: true, CARD: true, ACCOUNT: true, GSTIN: true, PASSPORT: true,
    DOB: true, BALANCE: true, PASSWORD: true, FACE: true,
  },
});

const PALETTE = Object.freeze({
  redaction: '#000000',
  redactionToken: '#ff3ea5',
  markStroke: '#00e5ff',
  markStrokeAlt: '#ffd400',
  markChipBg: '#00131a',
  markChipText: '#00e5ff',
  wireBg: '#0b1220',
  wireStroke: '#2b4a63',
  wireText: '#94a3b8',
});

const log = (...a) => console.log('[AAVARAN/veil]', ...a);
const warn = (...a) => console.warn('[AAVARAN/veil]', ...a);
const err = (...a) => console.error('[AAVARAN/veil]', ...a);

const VERHOEFF_D = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]);

const VERHOEFF_P = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]);

// Verhoeff checksum (UIDAI's Aadhaar check digit), real D5 tables.
function verhoeffValid(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length !== 12) return false;
  if (digits[0] === '0' || digits[0] === '1') return false; // UIDAI reserves 0/1
  let c = 0;
  const rev = digits.split('').reverse();
  for (let i = 0; i < rev.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(rev[i])]];
  }
  return c === 0;
}

function luhnValid(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Priority order: earlier rules claim their span first.
const RULES = [
  {
    kind: 'AADHAAR',
    re: /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
    validate: verhoeffValid,
    normalize: (s) => s.replace(/\D/g, ''),
  },
  {
    kind: 'CARD',
    re: /\b(?:\d[ \-]?){12,18}\d\b/g,
    validate: luhnValid,
    normalize: (s) => s.replace(/\D/g, ''),
  },
  {
    kind: 'GSTIN',
    re: /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b/g,
  },
  {
    kind: 'PAN',
    // 4th char is the holder type (P, C, H, F, A, T, B, L, J, G). The check
    // letter may OCR as a digit (O->0), so a trailing digit is accepted.
    re: /\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z0-9]\b/g,
  },
  {
    kind: 'IFSC',
    re: /\b[A-Z]{4}0[A-Z\d]{6}\b/g,
  },
  {
    kind: 'PASSPORT',
    re: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/g,
  },
  {
    kind: 'EMAIL',
    // Requires a dotted domain — this is what separates an email from a UPI VPA.
    // Unicode-aware: OCR turns "arjun66" into "arjuné6", and an ASCII class
    // would then match only the "6@…" tail.
    re: /(?<![\p{L}\p{N}._%+\-])[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.\p{L}{2,63}(?![\p{L}\p{N}])/gu,
    normalize: (s) => s.toLowerCase(),
  },
  {
    kind: 'UPI',
    // handle@psp with no dot in the PSP segment: rahul@okaxis, 98xxxx@ybl
    re: /(?<![\p{L}\p{N}._\-])[\p{L}\p{N}._\-]{2,64}@\p{L}{2,32}(?![\p{L}\p{N}]|\.\p{L})/gu,
    normalize: (s) => s.toLowerCase(),
  },
  {
    kind: 'PHONE',
    // Indian mobiles are written 9821447063, 98214 47063, and 982 144 7063.
    re: /(?:\+?91[\s\-]?|\b0)?\b[6-9]\d{4}[\s\-]?\d{5}\b|(?:\+?91[\s\-]?|\b0)?\b[6-9]\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b/g,
    validate: (s) => {
      const d = s.replace(/\D/g, '');
      const local = d.length > 10 ? d.slice(-10) : d;
      return local.length === 10 && /^[6-9]/.test(local);
    },
    normalize: (s) => s.replace(/\D/g, '').slice(-10),
  },
  {
    kind: 'DOB',
    re: /\b(?:0?[1-9]|[12]\d|3[01])[\/\-.](?:0?[1-9]|1[0-2])[\/\-.](?:19|20)\d{2}\b/g,
  },
  {
    kind: 'BALANCE',
    re: /(?:₹|Rs\.?|INR)\s?\d{1,3}(?:[,\d]{0,12})(?:\.\d{1,2})?/gi,
  },
  {
    kind: 'NAME',
    re: /(?<=\b(?:[Nn]ame|[Hh]older|[Nn]ominee)[ \t]*[:|\-]?[ \t]*)[A-Z](?:[a-z]+|\.)(?:[ \t]+[A-Zl](?:[a-z]+|\.)){0,3}/g,
  },
  {
    kind: 'ACCOUNT',
    // Catch-all for long digit runs that survived every checksum rule above.
    // Deliberately greedy: a false redaction costs a retry, a miss costs an
    // identity. Recall is the objective on the redaction path, not precision.
    re: /\b\d{9,18}\b/g,
  },
];
// Unvalidated identifier shapes (spaced 12-digit, masked, short IDs) from
// pii.hardening.js. Appended so checksum rules still claim their spans first.
RULES.push(...self.AAVARAN_PII.GROUPED_RULES);

function detectPiiSpans(text, kinds, extraRules = []) {
  if (!text) return [];
  const cands = [];

  // Collect all matches, then keep the longest span: rule order alone let AADHAAR claim a card's first 12 digits.
  [...RULES, ...extraRules].forEach((rule, prio) => {
    if (kinds && kinds[rule.kind] === false) return;
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      if (raw.length === 0) { rule.re.lastIndex++; continue; }
      if (rule.validate && !rule.validate(raw)) continue;
      cands.push({
        kind: rule.kind,
        start,
        end,
        raw,
        value: rule.normalize ? rule.normalize(raw) : raw.trim(),
        prio,
      });
    }
  });

  // Longest span wins; rule priority only breaks exact ties.
  cands.sort((a, b) =>
    (b.end - b.start) - (a.end - a.start) || a.prio - b.prio || a.start - b.start);

  const out = [];
  const claimed = new Uint8Array(text.length);
  for (const c of cands) {
    let overlaps = false;
    for (let i = c.start; i < c.end; i++) { if (claimed[i]) { overlaps = true; break; } }
    if (overlaps) continue;
    for (let i = c.start; i < c.end; i++) claimed[i] = 1;
    out.push(c);
  }
  out.sort((a, b) => a.start - b.start);
  return out;
}

async function vaultKey(kind, value) {
  const bytes = new TextEncoder().encode(`${kind}|${value}`);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Token identity derives from the value, so a repeated value gets the same token.
class TokenVault {
  constructor(known) {
    this.map = new Map(Object.entries(known || {}));  // vaultKey -> token
    this.fresh = [];                                  // entries to persist
    this.counters = new Map();                        // kind -> highest index
    for (const token of this.map.values()) {
      const m = /^<PII:([A-Z_]+)#(\d+)>$/.exec(token);
      if (!m) continue;
      const n = Number(m[2]);
      if (n > (this.counters.get(m[1]) || 0)) this.counters.set(m[1], n);
    }
  }

  async tokenFor(kind, value) {
    const key = await vaultKey(kind, value);
    const existing = this.map.get(key);
    if (existing) return existing;
    const next = (this.counters.get(kind) || 0) + 1;
    this.counters.set(kind, next);
    const token = `<PII:${kind}#${next}>`;
    this.map.set(key, token);
    this.fresh.push({ hashKey: key, token, kind, value });
    return token;
  }

  async tokenize(text, kinds, extraRules) {
    if (!text) return { text: text || '', tokens: [] };
    const spans = detectPiiSpans(text, kinds, extraRules);
    if (!spans.length) return { text, tokens: [] };
    let out = '';
    let cursor = 0;
    const tokens = [];
    for (const s of spans) {
      const token = await this.tokenFor(s.kind, s.value);
      out += text.slice(cursor, s.start) + token;
      cursor = s.end;
      tokens.push({ token, kind: s.kind });
    }
    out += text.slice(cursor);
    return { text: out, tokens };
  }
}

const OCR = {
  worker: null,
  initPromise: null,
  queue: Promise.resolve(),
  lastUsed: 0,
  idleTimer: null,
  failed: false,
  failReason: '',
  IDLE_MS: 5 * 60 * 1000,
};

// A 0-byte wasm asset (aborted download) makes Tesseract fail opaquely; check sizes up front.
let assetsOk = false;

async function assertLocalAssets() {
  // Packaged files cannot change while the document lives; re-fetching ~12 MB
  // on every frame was most of the per-step latency.
  if (assetsOk) return [];
  const required = [
    ['libs/tesseract.min.js', 40_000],
    ['libs/worker.min.js', 10_000],
    ['libs/tesseract-core.wasm.js', 100_000],
    // The .wasm.js is emscripten glue; this is the payload it fetches at runtime.
    ['libs/tesseract-core.wasm', 2_000_000],
    ['libs/tessdata/eng.traineddata', 1_000_000],
    ['libs/face-api.min.js', 100_000],
    ['libs/models/tiny_face_detector_model-weights_manifest.json', 100],
    ['libs/models/tiny_face_detector_model-shard1', 100_000],
  ];
  const problems = [];
  for (const [rel, minBytes] of required) {
    try {
      const res = await fetch(chrome.runtime.getURL(rel));
      if (!res.ok) { problems.push(`${rel}: HTTP ${res.status}`); continue; }
      const buf = await res.arrayBuffer();
      if (buf.byteLength < minBytes) {
        problems.push(`${rel}: ${buf.byteLength} bytes (expected >= ${minBytes})`);
      }
    } catch (e) {
      problems.push(`${rel}: ${e.message}`);
    }
  }
  assetsOk = problems.length === 0;
  return problems;
}

async function initOcr() {
  if (OCR.worker) return OCR.worker;
  if (OCR.initPromise) return OCR.initPromise;

  OCR.initPromise = (async () => {
    const t0 = performance.now();
    const worker = await Tesseract.createWorker('eng', 1, {
      // Every path is a chrome-extension:// URL. Nothing is fetched remotely,
      // which is both the privacy requirement and the only way MV3's CSP will
      // permit the worker to start.
      workerPath: chrome.runtime.getURL('libs/worker.min.js'),
      corePath: chrome.runtime.getURL('libs/tesseract-core.wasm.js'),
      langPath: chrome.runtime.getURL('libs/tessdata'),
      // The bundled traineddata is uncompressed; without this, tesseract.js
      // appends `.gz` and the fetch 404s.
      gzip: false,
      // Blob-URL workers are blocked by the extension_pages CSP. Loading the
      // worker straight from its packaged URL keeps it same-origin.
      workerBlobURL: false,
      // Assets are already local; the IndexedDB cache is pure overhead here.
      cacheMethod: 'none',
      logger: () => {},
      errorHandler: (e) => err('tesseract worker error:', e),
    });
    await worker.setParameters({
      tessedit_pageseg_mode: Tesseract.PSM ? Tesseract.PSM.AUTO : '3',
      preserve_interword_spaces: '1',
    });
    log(`tesseract ready in ${Math.round(performance.now() - t0)}ms`);
    OCR.worker = worker;
    return worker;
  })().catch((e) => {
    OCR.failed = true;
    OCR.failReason = e && e.message ? e.message : String(e);
    OCR.initPromise = null;
    throw e;
  });

  return OCR.initPromise;
}

function scheduleOcrIdleRelease() {
  if (OCR.idleTimer) clearTimeout(OCR.idleTimer);
  OCR.idleTimer = setTimeout(async () => {
    if (!OCR.worker) return;
    if (Date.now() - OCR.lastUsed < OCR.IDLE_MS) return;
    try { await OCR.worker.terminate(); } catch { /* already gone */ }
    OCR.worker = null;
    OCR.initPromise = null;
    log('tesseract worker released after idle');
  }, OCR.IDLE_MS + 1000);
}

function ocrRecognize(blob) {
  const job = OCR.queue.then(async () => {
    const worker = await initOcr();
    // tesseract.js v6+ no longer returns the word tree unless asked.
    const result = await worker.recognize(blob, {}, { blocks: true });
    OCR.lastUsed = Date.now();
    scheduleOcrIdleRelease();
    return result.data;
  });
  OCR.queue = job.catch(() => {});
  return job;
}

function flattenWords(data) {
  if (Array.isArray(data.words) && data.words.length) {
    // Map each word's parent-line reference to a dense index; fall back to bucketing by baseline y.
    const lineIds = new Map();
    return data.words.map((w) => {
      let line;
      if (w.line && typeof w.line === 'object') {
        if (!lineIds.has(w.line)) lineIds.set(w.line, lineIds.size);
        line = lineIds.get(w.line);
      } else {
        const mid = w.bbox ? Math.round((w.bbox.y0 + w.bbox.y1) / 2 / 12) : 0;
        if (!lineIds.has(mid)) lineIds.set(mid, lineIds.size);
        line = lineIds.get(mid);
      }
      return {
        text: w.text || '',
        bbox: w.bbox,
        confidence: typeof w.confidence === 'number' ? w.confidence : 0,
        line,
      };
    });
  }
  const out = [];
  let lineIdx = 0;
  for (const block of data.blocks || []) {
    for (const para of block.paragraphs || []) {
      for (const line of para.lines || []) {
        for (const w of line.words || []) {
          out.push({
            text: w.text || '',
            bbox: w.bbox,
            confidence: typeof w.confidence === 'number' ? w.confidence : 0,
            line: lineIdx,
          });
        }
        lineIdx++;
      }
    }
  }
  return out;
}

function buildTextIndex(words) {
  let text = '';
  const map = []; // { start, end, wordIdx }
  let prevLine = words.length ? words[0].line : 0;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (i > 0) {
      const p = words[i - 1];
      const h = Math.max(1, w.bbox.y1 - w.bbox.y0);
      // A wide horizontal gap is a column break: keeps "Name | Meera Reddy"
      // adjacent for label rules without fusing unrelated columns.
      text += w.line !== prevLine ? '\n' : (w.bbox.x0 - p.bbox.x1 > 2.5 * h ? ' | ' : ' ');
    }
    const start = text.length;
    text += w.text;
    map.push({ start, end: text.length, wordIdx: i });
    prevLine = w.line;
  }
  return { text, map };
}

// Tesseract splits two-column forms into label and value blocks; rebuild visual rows from geometry.
function relineWords(words) {
  const sorted = words.slice().sort((a, b) => (a.bbox.y0 + a.bbox.y1) - (b.bbox.y0 + b.bbox.y1));
  let line = -1;
  let lineMid = -Infinity;
  let lineH = 0;
  for (const w of sorted) {
    const mid = (w.bbox.y0 + w.bbox.y1) / 2;
    const h = w.bbox.y1 - w.bbox.y0;
    if (Math.abs(mid - lineMid) > Math.max(3, Math.min(h, lineH) * 0.5)) {
      line++; lineMid = mid; lineH = h;
    }
    w.line = line;
  }
  return sorted.sort((a, b) => a.line - b.line || a.bbox.x0 - b.bbox.x0);
}

function readingLines(words) {
  const lines = [];
  let last = null;
  for (const w of words) {
    if (w.confidence < 40) continue;
    if (w.line !== last) { lines.push(w.text); last = w.line; } else lines[lines.length - 1] += ` ${w.text}`;
  }
  return lines;
}

function wordsInSpan(map, start, end) {
  const hits = [];
  for (const entry of map) {
    if (entry.end <= start) continue;
    if (entry.start >= end) break;
    hits.push(entry.wordIdx);
  }
  return hits;
}

const FACE = { loaded: false, loading: null, backend: null, inputMode: null, failed: false };

async function initFaces() {
  if (FACE.loaded) return true;
  if (FACE.loading) return FACE.loading;

  FACE.loading = (async () => {
    const t0 = performance.now();
    for (const backend of ['webgl', 'cpu']) {
      try {
        await faceapi.tf.setBackend(backend);
        await faceapi.tf.ready();
        FACE.backend = backend;
        break;
      } catch (e) {
        warn(`tfjs backend ${backend} unavailable:`, e.message);
      }
    }
    if (!FACE.backend) throw new Error('no usable tfjs backend');
    // Path only: face-api's URI parser knows http(s):// and turns
    // "chrome-extension://id/x" into "chrome-extension:/id/x", which 404s.
    const modelPath = new URL(chrome.runtime.getURL('libs/models'), location.href).pathname;
    await faceapi.nets.tinyFaceDetector.loadFromUri(modelPath);
    FACE.loaded = true;
    log(`face-api ready (${FACE.backend}) in ${Math.round(performance.now() - t0)}ms`);
    return true;
  })().catch((e) => {
    FACE.failed = true;
    FACE.loading = null;
    throw e;
  });

  return FACE.loading;
}

// face-api's bundled tfjs 1.x predates OffscreenCanvas: probe input shapes once, DOM canvas as the floor.
async function faceTensorFrom(canvas) {
  const w = canvas.width;
  const h = canvas.height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  const attempts = {
    offscreen: () => faceapi.tf.browser.fromPixels(canvas),
    imagedata: () => faceapi.tf.browser.fromPixels(ctx.getImageData(0, 0, w, h)),
    pixeldata: () => {
      const id = ctx.getImageData(0, 0, w, h);
      return faceapi.tf.browser.fromPixels(
        { data: new Uint8Array(id.data.buffer), width: w, height: h }, 3,
      );
    },
    domcanvas: () => {
      const dom = document.getElementById('veilCanvas');
      dom.width = w; dom.height = h;
      dom.getContext('2d').drawImage(canvas, 0, 0);
      return faceapi.tf.browser.fromPixels(dom);
    },
  };

  const order = FACE.inputMode
    ? [FACE.inputMode, ...Object.keys(attempts).filter((k) => k !== FACE.inputMode)]
    : Object.keys(attempts);

  let lastError = null;
  for (const mode of order) {
    try {
      const tensor = attempts[mode]();
      FACE.inputMode = mode;
      return tensor;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error('no viable face-api input adapter');
}

const NER = { pipe: null, loading: null, failed: false, reason: '', device: null };
const NER_MAX_LINES = 240;     // bounds latency on huge pages; rules still cover the rest
const NER_LINE_CHARS = 400;    // ~100 wordpieces, well inside the 512 limit
const NER_MIN_SCORE = 0.3;     // recall-first: a false redaction costs a retry

async function nerDevice() {
  try {
    if (navigator.gpu && await navigator.gpu.requestAdapter()) return 'webgpu';
  } catch (e) { /* no adapter */ }
  return 'wasm';
}

function initNer() {
  if (NER.pipe || NER.failed) return Promise.resolve(NER.pipe);
  NER.loading = NER.loading || (async () => {
    const T = await import(chrome.runtime.getURL('libs/transformers/transformers.min.js'));
    T.env.allowRemoteModels = false;
    T.env.allowLocalModels = true;
    T.env.useBrowserCache = false;
    T.env.localModelPath = chrome.runtime.getURL('libs/models/');
    T.env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('libs/transformers/');
    // Extension pages are not cross-origin isolated: no SharedArrayBuffer threads.
    T.env.backends.onnx.wasm.numThreads = 1;
    const first = await nerDevice();
    for (const device of first === 'wasm' ? ['wasm'] : [first, 'wasm']) {
      try {
        const t0 = performance.now();
        const pipe = await T.pipeline('token-classification', 'ner', { device, dtype: 'int8' });
        // Probe the OUTPUT, not just availability: int8 on the WebGPU EP loads
        // fine and returns noise. A backend that cannot find this name is broken.
        const probe = await pipe('My name is Rahul Sharma.');
        if (!probe.some((t) => /PERSON$/.test(t.entity) && t.score >= 0.5)) {
          throw new Error('failed the output probe');
        }
        NER.pipe = pipe;
        NER.device = device;
        log(`NER ready (${device}) in ${Math.round(performance.now() - t0)}ms`);
        return NER.pipe;
      } catch (e) {
        warn(`NER on ${device} unavailable:`, e.message);
      }
    }
    throw new Error('no NER execution provider');
  })().catch((e) => {
    NER.failed = true;
    NER.reason = e && e.message ? e.message : String(e);
    return null;
  });
  return NER.loading;
}

// One input per visual line: the prose-trained model finds nothing inside a block of form rows.
function nerLines(texts) {
  const lines = new Set();
  for (const raw of texts.join('\n').split('\n')) {
    const line = raw.replace(/\s+\|\s+/g, ': ').trim().slice(0, NER_LINE_CHARS);
    if (/[A-Za-z]{2}/.test(line)) lines.add(line);
  }
  return [...lines].slice(0, NER_MAX_LINES);
}

function personPatterns(tokens) {
  const names = [];
  let cur = null;
  let lastIdx = -2;
  for (const t of tokens) {
    const isPerson = /^[BI]-PERSON$/.test(t.entity) && t.score >= NER_MIN_SCORE;
    if (!isPerson) { cur = null; continue; }
    if (!cur || (t.entity.startsWith('B-') && !t.word.startsWith('##')) || t.index !== lastIdx + 1) {
      cur = [];
      names.push(cur);
    }
    cur.push(t.word);
    lastIdx = t.index;
  }
  // The model is uncased: match each piece case-insensitively via [aA]
  // classes, so the surrounding regex can stay case-sensitive (see nerRules).
  const caseless = (p) => p.replace(/[a-z]/g, (c) => `[${c}${c.toUpperCase()}]`);
  const out = new Set();
  for (const pieces of names) {
    let re = '';
    for (const w of pieces) {
      const esc = caseless(w.replace(/^##/, '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
      re += w.startsWith('##') || !re ? esc : `\\s*${esc}`;
    }
    if (pieces.join('').replace(/[^A-Za-z]/g, '').length >= 3) out.add(re);
  }
  return [...out];
}

async function nerRules(texts, timings, warnings) {
  const t0 = performance.now();
  try {
    const pipe = await initNer();
    if (!pipe) {
      if (NER.reason) warnings.push(`ner_unavailable: ${NER.reason}`);
      return [];
    }
    const chunks = nerLines(texts);
    if (!chunks.length) return [];
    const results = await pipe(chunks);
    // A single input returns a flat list; several return a list per input.
    const perChunk = chunks.length === 1 ? [results] : results;
    const patterns = new Set();
    for (const tokens of perChunk) for (const p of personPatterns(tokens)) patterns.add(p);
    if (!patterns.size) return [];
    // Case-sensitive tail: the one capitalised word that follows a found name
    // (a surname the model scored too low) is taken too. "l" stands in for a
    // capital I, which OCR routinely misreads ("Iyer" -> "lyer").
    const alt = [...patterns].sort((a, b) => b.length - a.length).join('|');
    return [{
      kind: 'NAME',
      re: new RegExp(`(?<![A-Za-z])(?:${alt})(?:[ \\t]+[A-Zl][a-z]+)?(?![A-Za-z])`, 'g'),
    }];
  } catch (e) {
    warnings.push(`ner_failed: ${e.message}`);
    return [];
  } finally {
    timings.ner = Math.round(performance.now() - t0);
  }
}

async function bitmapFromDataUrl(dataUrl) {
  const blob = await (await fetch(dataUrl)).blob();
  return { bitmap: await createImageBitmap(blob), bytes: blob.size };
}

function makeCanvas(w, h) {
  const c = new OffscreenCanvas(Math.max(1, Math.round(w)), Math.max(1, Math.round(h)));
  return { canvas: c, ctx: c.getContext('2d', { willReadFrequently: true }) };
}

function scaledCopy(src, maxEdge) {
  const longEdge = Math.max(src.width, src.height);
  const scale = longEdge > maxEdge ? maxEdge / longEdge : 1;
  if (scale === 1) return { canvas: src, scale: 1 };
  const { canvas, ctx } = makeCanvas(src.width * scale, src.height * scale);
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(src, 0, 0, canvas.width, canvas.height);
  return { canvas, scale };
}

async function canvasToBlob(canvas, type = 'image/png', quality) {
  return canvas.convertToBlob(quality ? { type, quality } : { type });
}

function blobToDataUrl(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error('FileReader failed'));
    reader.readAsDataURL(blob);
  });
}

function normBox(x0, y0, x1, y1, pad, w, h) {
  const nx0 = Math.max(0, Math.floor(Math.min(x0, x1) - pad));
  const ny0 = Math.max(0, Math.floor(Math.min(y0, y1) - pad));
  const nx1 = Math.min(w, Math.ceil(Math.max(x0, x1) + pad));
  const ny1 = Math.min(h, Math.ceil(Math.max(y0, y1) + pad));
  return [nx0, ny0, nx1, ny1];
}

function boxArea(b) { return Math.max(0, b[2] - b[0]) * Math.max(0, b[3] - b[1]); }

// A 'face' box mostly covered by confident OCR text is a text block, not a face.
function isTextBlock(box, words, scale) {
  let n = 0;
  let covered = 0;
  for (const w of words) {
    if (w.confidence < 70) continue;
    const wb = [w.bbox.x0 / scale, w.bbox.y0 / scale, w.bbox.x1 / scale, w.bbox.y1 / scale];
    const inter = boxIntersect(box, wb);
    if (!inter) continue;
    n++;
    covered += boxArea(inter);
  }
  return n >= 6 && covered / boxArea(box) >= 0.10;
}

function boxIntersect(a, b) {
  const x0 = Math.max(a[0], b[0]);
  const y0 = Math.max(a[1], b[1]);
  const x1 = Math.min(a[2], b[2]);
  const y1 = Math.min(a[3], b[3]);
  return x1 <= x0 || y1 <= y0 ? null : [x0, y0, x1, y1];
}

function mergeBoxes(boxes, gap = 6) {
  const out = [];
  const used = new Array(boxes.length).fill(false);
  for (let i = 0; i < boxes.length; i++) {
    if (used[i]) continue;
    let cur = boxes[i].slice();
    used[i] = true;
    let merged = true;
    while (merged) {
      merged = false;
      for (let j = 0; j < boxes.length; j++) {
        if (used[j]) continue;
        const b = boxes[j];
        const grown = [cur[0] - gap, cur[1] - gap, cur[2] + gap, cur[3] + gap];
        if (boxIntersect(grown, b)) {
          cur = [
            Math.min(cur[0], b[0]), Math.min(cur[1], b[1]),
            Math.max(cur[2], b[2]), Math.max(cur[3], b[3]),
          ];
          used[j] = true;
          merged = true;
        }
      }
    }
    out.push(cur);
  }
  return out;
}

// dHash of the veiled pre-mark frame, so mark renumbering is not seen as a page change.
function perceptualHash(canvas) {
  const { canvas: small, ctx } = makeCanvas(9, 8);
  ctx.imageSmoothingEnabled = true;
  ctx.drawImage(canvas, 0, 0, 9, 8);
  const { data } = ctx.getImageData(0, 0, 9, 8);
  const gray = new Float32Array(72);
  for (let i = 0; i < 72; i++) {
    const o = i * 4;
    gray[i] = 0.299 * data[o] + 0.587 * data[o + 1] + 0.114 * data[o + 2];
  }
  let bits = '';
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      bits += gray[y * 9 + x] > gray[y * 9 + x + 1] ? '1' : '0';
    }
  }
  let hex = '';
  for (let i = 0; i < 64; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  void small;
  return hex;
}

async function markSignature(marks) {
  const payload = marks
    .map((m) => `${m.role}|${m.name}|${m.editable ? 1 : 0}|${m.bbox.map((v) => Math.round(v / 8)).join(',')}`)
    .sort()
    .join(';');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  return [...new Uint8Array(digest)].slice(0, 8)
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Exact-match key, no perceptual part: a coarse key would reuse stale boxes after new PII appears.
async function veilReuseKey(payload) {
  const meta = JSON.stringify([
    payload.domMarks || [], payload.opaque || [], payload.viewport || {}, payload.config || {},
    Object.entries(payload.knownTokens || {}).sort(),
  ]);
  // JSON escapes newlines, so this separator cannot be forged by the meta part.
  const bytes = new TextEncoder().encode(`${meta}\n${payload.rawDataUrl || ''}`);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// The VLM answers with a mark index, never a coordinate.
function drawMarks(ctx, marks, opts) {
  const fontSize = opts.fontSize;
  const chipH = Math.round(fontSize * 1.55);
  const placed = [];

  ctx.save();
  ctx.lineJoin = 'miter';
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'center';

  for (const mark of marks) {
    const [x0, y0, x1, y1] = mark.bbox;
    const stroke = mark.editable ? PALETTE.markStrokeAlt : PALETTE.markStroke;

    ctx.lineWidth = opts.lineWidth;
    ctx.strokeStyle = stroke;
    ctx.globalAlpha = 0.95;
    ctx.strokeRect(x0 + 0.5, y0 + 0.5, Math.max(1, x1 - x0 - 1), Math.max(1, y1 - y0 - 1));
    ctx.globalAlpha = 1;

    const label = String(mark.id);
    ctx.font = `700 ${fontSize}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`;
    const chipW = Math.max(chipH, Math.round(ctx.measureText(label).width) + fontSize);

    // Preference order: outside top-left, inside top-left, outside top-right,
    // inside top-right, outside bottom-left, inside bottom-left.
    const candidates = [
      [x0, y0 - chipH], [x0, y0], [x1 - chipW, y0 - chipH],
      [x1 - chipW, y0], [x0, y1], [x0, y1 - chipH],
    ];

    let pos = candidates[0];
    for (const c of candidates) {
      const box = [c[0], c[1], c[0] + chipW, c[1] + chipH];
      if (box[0] < 0 || box[1] < 0 || box[2] > opts.width || box[3] > opts.height) continue;
      if (placed.some((p) => boxIntersect(p, box))) continue;
      pos = c;
      break;
    }
    const cx = Math.max(0, Math.min(opts.width - chipW, pos[0]));
    const cy = Math.max(0, Math.min(opts.height - chipH, pos[1]));
    placed.push([cx, cy, cx + chipW, cy + chipH]);

    ctx.fillStyle = PALETTE.markChipBg;
    ctx.fillRect(cx, cy, chipW, chipH);
    ctx.strokeStyle = stroke;
    ctx.lineWidth = Math.max(1, opts.lineWidth - 1);
    ctx.strokeRect(cx + 0.5, cy + 0.5, chipW - 1, chipH - 1);
    ctx.fillStyle = stroke;
    ctx.fillText(label, cx + chipW / 2, cy + chipH / 2 + 0.5);
  }

  ctx.restore();
}

async function veil(payload) {
  const cfg = { ...DEFAULTS, ...(payload.config || {}) };
  cfg.kinds = { ...DEFAULTS.kinds, ...((payload.config && payload.config.kinds) || {}) };
  // Recall profile by origin: banking/gov hosts get the paranoid floor.
  const profile = AAVARAN_HARDEN.profileFor((payload.viewport || {}).url, cfg.profile);
  cfg.ocrConfFloor = Math.max(cfg.ocrConfFloor, profile.ocrConfFloor);

  // Per-run state (stable ids, delta base). A panel capture has no session
  // and must not disturb a run's delta chain.
  const track = !!payload.sessionId;
  if (track && RUN.sessionId !== payload.sessionId) {
    RUN.sessionId = payload.sessionId;
    RUN.ids = new AAVARAN_DELTA.StableMarkIds();
    RUN.grid = null;
    RUN.sinceKeyframe = 0;
    RUN.reuse = null;
  }

  const timings = {};
  const warnings = [];
  const t0 = performance.now();

  const { bitmap, bytes: bytesRaw } = await bitmapFromDataUrl(payload.rawDataUrl);
  const devW = bitmap.width;
  const devH = bitmap.height;

  const { canvas: full, ctx: fullCtx } = makeCanvas(devW, devH);
  fullCtx.drawImage(bitmap, 0, 0);
  bitmap.close();
  timings.decode = Math.round(performance.now() - t0);

  // DPR measured from the bitmap, not window.devicePixelRatio, so it also absorbs browser and pinch zoom.
  const vp = payload.viewport || {};
  const vvW = Number(vp.vvWidth) || Number(vp.cssWidth) || devW;
  const vvH = Number(vp.vvHeight) || Number(vp.cssHeight) || devH;
  const dprX = devW / vvW;
  const dprY = devH / vvH;
  const offL = Number(vp.vvOffsetLeft) || 0;
  const offT = Number(vp.vvOffsetTop) || 0;

  if (Math.abs(dprX - dprY) > 0.02) {
    warnings.push(`anisotropic capture scale x=${dprX.toFixed(3)} y=${dprY.toFixed(3)}`);
  }

  const cssToDev = (r) => [
    (r.x - offL) * dprX,
    (r.y - offT) * dprY,
    (r.x - offL + r.w) * dprX,
    (r.y - offT + r.h) * dprY,
  ];
  const devToCss = (b) => ({
    x: b[0] / dprX + offL,
    y: b[1] / dprY + offT,
    w: (b[2] - b[0]) / dprX,
    h: (b[3] - b[1]) / dprY,
  });

  /* An identical repeat of the previous frame in this run (same bytes, same
   * DOM, same vault) reuses its detections and skips faces/OCR/NER. */
  const reuseKey = track ? await veilReuseKey(payload) : null;
  const reused = reuseKey && RUN.reuse && RUN.reuse.key === reuseKey ? RUN.reuse : null;
  const stageWarnings = warnings.length;

  // Started here, awaited after OCR: tfjs on this thread overlaps the Tesseract worker.
  const redactions = [];
  const redactionLabels = [];
  let facesRedacted = 0;
  const faceBoxes = [];
  let faceOk = false;

  const faceStage = !reused && cfg.enableFaces && cfg.kinds.FACE && (async () => {
    const tf0 = performance.now();
    let tensor = null;
    try {
      await initFaces();
      const { canvas: small, scale } = scaledCopy(full, cfg.faceMaxEdge);
      tensor = await faceTensorFrom(small);
      const dets = await faceapi.detectAllFaces(
        tensor,
        new faceapi.TinyFaceDetectorOptions({ inputSize: 1024, scoreThreshold: profile.faceScore }),
      );
      for (const d of dets) {
        const { x, y, width, height } = d.box;
        // Dilate generously: a tight crop around a face still leaves hairline,
        // ear and jaw pixels that are individually re-identifiable.
        const padX = width * 0.22;
        const padY = height * 0.28;
        faceBoxes.push(normBox(
          (x - padX) / scale, (y - padY) / scale,
          (x + width + padX) / scale, (y + height + padY) / scale,
          cfg.redactionPad, devW, devH,
        ));
      }
      faceOk = true;
    } catch (e) {
      warn('face detection failed:', e);
      warnings.push(`face_detection_failed: ${e.message}`);
    } finally {
      if (tensor && typeof tensor.dispose === 'function') tensor.dispose();
    }
    timings.faces = Math.round(performance.now() - tf0);
  })();

  const vault = new TokenVault(payload.knownTokens);
  const piiFound = [];
  let ocrOk = false;
  let wordsScanned = 0;
  let ocrWords = [];
  let ocrScale = 1;
  let textRegions = 0;
  let failClosedRegions = 0;
  const domMarks = Array.isArray(payload.domMarks) ? payload.domMarks : [];
  // Text-channel strings that also leave (or may be redacted): run NER over
  // them in the same pass as the OCR text.
  const nerTexts = [vp.title || '', ...domMarks.map((m) => `${m.name || ''}\n${m.value || ''}`)];
  let extraRules = [];
  let nerDone = false;

  if (!reused && cfg.enableOcr) {
    const to0 = performance.now();
    try {
      const assetProblems = await assertLocalAssets();
      if (assetProblems.length) {
        throw new Error(`local asset preflight failed → ${assetProblems.join('; ')}`);
      }

      const ocrEdge = Math.min(cfg.ocrMaxEdge, Math.max(vvW, vvH) * cfg.ocrCssScale);
      const { canvas: ocrCanvas, scale } = scaledCopy(full, ocrEdge);
      ocrScale = scale;
      const data = await ocrRecognize(await canvasToBlob(ocrCanvas));
      ocrWords = relineWords(flattenWords(data).filter((w) => w.text && w.text.trim() && w.bbox));
      wordsScanned = ocrWords.length;
      // Text without word boxes cannot be located, so cannot be redacted.
      // That is an OCR failure (wireframe/block), never a "clean" frame.
      if (!ocrWords.length && String(data.text || '').trim()) {
        throw new Error('OCR returned text but no word geometry');
      }

      const { text, map } = buildTextIndex(ocrWords);
      extraRules = await nerRules([text, ...nerTexts], timings, warnings);
      nerDone = true;
      const spans = detectPiiSpans(text, cfg.kinds, extraRules);
      const claimed = new Set();

      for (const span of spans) {
        const idxs = wordsInSpan(map, span.start, span.end);
        if (!idxs.length) continue;
        for (const i of idxs) claimed.add(i);
        // One box per visual line: a span that wraps must not become a
        // rectangle covering every unrelated row in between.
        const perLine = new Map();
        for (const i of idxs) {
          const b = ocrWords[i].bbox;
          const r = perLine.get(ocrWords[i].line);
          perLine.set(ocrWords[i].line, r
            ? [Math.min(r[0], b.x0), Math.min(r[1], b.y0), Math.max(r[2], b.x1), Math.max(r[3], b.y1)]
            : [b.x0, b.y0, b.x1, b.y1]);
        }
        const token = await vault.tokenFor(span.kind, span.value);
        piiFound.push({ token, kind: span.kind });
        let first = true;
        for (const [x0, y0, x1, y1] of perLine.values()) {
          const box = normBox(x0 / scale, y0 / scale, x1 / scale, y1 / scale, cfg.redactionPad, devW, devH);
          if (first) redactionLabels.push({ box, token, kind: span.kind });
          first = false;
          redactions.push(box);
        }
      }

      /* Fail-closed bands (offscreen.hardening.js): low-confidence numerics,
       * values on a labelled line ("A/c No"), and site-masked forms are
       * redacted on suspicion — the cases a checksum cannot rescue. */
      const fc = AAVARAN_HARDEN.failClosedBoxes(
        ocrWords, cfg, profile, scale, devW, devH, normBox, claimed);
      redactions.push(...fc.boxes);
      failClosedRegions += fc.boxes.length;
      if (fc.boxes.length) piiFound.push({ token: '<PII:UNREADABLE>', kind: 'LOW_CONFIDENCE' });

      textRegions = redactionLabels.length;
      ocrOk = true;
    } catch (e) {
      err('OCR stage failed:', e);
      warnings.push(`ocr_failed: ${e.message}`);
    }
    timings.ocr = Math.round(performance.now() - to0);
  }
  if (!reused && !nerDone) extraRules = await nerRules(nerTexts, timings, warnings);
  if (faceStage) await faceStage;   // never rejects: failure leaves faceOk false

  // tinyFaceDetector at a recall-first threshold fires on dense text blocks;
  // one such hit blacked out a whole identity card, labels included, which
  // blinds the agent. Without OCR there is no evidence, so every face stays.
  for (const box of faceBoxes) {
    if (ocrOk && isTextBlock(box, ocrWords, ocrScale)) {
      warnings.push('face_rejected_text_block');
      continue;
    }
    redactions.push(box);
    facesRedacted++;
  }

  if (reused) {
    ({ faceOk, ocrOk, facesRedacted, wordsScanned, ocrWords, ocrScale, textRegions,
      failClosedRegions, extraRules } = reused);
    // Same knownTokens, same order: the vault re-issues the identical tokens
    // (and newVaultEntries) the original pass produced.
    for (const f of reused.fresh) await vault.tokenFor(f.kind, f.value);
    redactions.push(...reused.redactions);
    redactionLabels.push(...reused.redactionLabels);
    piiFound.push(...reused.piiFound);
    warnings.push(...reused.warnings);
    timings.reused = true;
  } else if (track) {
    // Only a fully successful pass is reusable; a failed stage must retry.
    const complete = (!cfg.enableOcr || ocrOk) && (!(cfg.enableFaces && cfg.kinds.FACE) || faceOk);
    RUN.reuse = complete ? {
      key: reuseKey, faceOk, ocrOk, facesRedacted, wordsScanned, ocrWords, ocrScale,
      textRegions, failClosedRegions, extraRules,
      fresh: vault.fresh.slice(), redactions: redactions.slice(),
      redactionLabels: redactionLabels.slice(), piiFound: piiFound.slice(),
      warnings: warnings.slice(stageWarnings),
    } : null;
  }

  /* Face model down: "0 faces" would be a lie, the truth is "unknown". Destroy
   * every image/video/canvas region large enough to hold a face instead. */
  if (cfg.enableFaces && cfg.kinds.FACE && !faceOk && profile.opaqueFallback) {
    const boxes = AAVARAN_HARDEN.opaqueFallbackBoxes(payload, cssToDev, normBox, cfg, devW, devH);
    redactions.push(...boxes);
    failClosedRegions += boxes.length;
  }

  // DOM channel: passwords render as bullets, so OCR cannot see what the DOM knows is sensitive.
  for (const dm of domMarks) {
    let sensitive = !!dm.sensitive;
    let kind = dm.sensitiveKind || 'PASSWORD';

    if (!sensitive && dm.value) {
      const spans = detectPiiSpans(String(dm.value), cfg.kinds, extraRules);
      if (spans.length) { sensitive = true; kind = spans[0].kind; }
    }
    if (!sensitive) continue;
    if (cfg.kinds[kind] === false) continue;

    const box = normBox(...cssToDev(dm.rect), cfg.redactionPad, devW, devH);
    if (boxArea(box) <= 0) continue;
    redactions.push(box);
    // An empty field is redacted but not tokenized: a placeholder value would
    // rehydrate into the page as literal text.
    if (dm.value) {
      const token = await vault.tokenFor(kind, String(dm.value));
      piiFound.push({ token, kind });
      redactionLabels.push({ box, token, kind });
    }
    textRegions++;
  }

  const unsafe = cfg.enableOcr && !ocrOk;
  if (unsafe && cfg.failMode === 'block') {
    return {
      ok: false,
      blocked: true,
      reason: 'veil_incomplete',
      veil: {
        mode: 'blocked', ocrOk, faceOk, wordsScanned, textRegionsRedacted: 0,
        facesRedacted, pii: [], confidenceFloor: cfg.ocrConfFloor, timings,
      },
      warnings,
    };
  }

  const tf = performance.now();
  const merged = mergeBoxes(redactions, Math.max(4, cfg.redactionPad));
  fullCtx.save();
  fullCtx.fillStyle = PALETTE.redaction;
  for (const b of merged) fullCtx.fillRect(b[0], b[1], b[2] - b[0], b[3] - b[1]);
  fullCtx.restore();
  timings.fill = Math.round(performance.now() - tf);

  // From here on the sensitive pixels do not exist in this buffer. Every later
  // stage — downscale, mark overlay, PNG encode — operates on destroyed data,
  // which is why a server-side crop, upscale or re-encode cannot recover them.

  const pixelHash = perceptualHash(full);

  const { canvas: egress, scale: egressScale } = scaledCopy(full, cfg.egressMaxEdge);
  const egressCanvas = egress === full ? makeCanvas(devW, devH).canvas : egress;
  if (egress === full) {
    egressCanvas.getContext('2d').drawImage(full, 0, 0);
  }
  const egCtx = egressCanvas.getContext('2d');
  const egW = egressCanvas.width;
  const egH = egressCanvas.height;
  const devToEgress = (b) => [b[0] * egressScale, b[1] * egressScale, b[2] * egressScale, b[3] * egressScale];

  if (cfg.labelRedactions && redactionLabels.length) {
    egCtx.save();
    egCtx.textBaseline = 'middle';
    for (const item of redactionLabels) {
      const b = devToEgress(item.box);
      const bw = b[2] - b[0];
      const bh = b[3] - b[1];
      if (bw < 90 || bh < 11) continue;
      const fs = Math.max(9, Math.min(15, Math.floor(bh * 0.62)));
      egCtx.font = `600 ${fs}px ui-monospace, Menlo, Consolas, monospace`;
      const label = item.token;
      if (egCtx.measureText(label).width > bw - 8) continue;
      egCtx.fillStyle = PALETTE.redactionToken;
      egCtx.fillText(label, b[0] + 4, b[1] + bh / 2);
    }
    egCtx.restore();
  }

  const marks = [];
  let markId = 0;

  const ranked = domMarks
    .map((dm) => ({ dm, box: normBox(...cssToDev(dm.rect), 0, devW, devH) }))
    .filter((x) => boxArea(x.box) > 16)
    .sort((a, b) => {
      // Reading order, bucketed so a 3px vertical wobble does not reshuffle
      // a toolbar row. Stable numbering across steps keeps the model's
      // references meaningful when it reasons over its own history.
      const ra = Math.round(a.box[1] / 24);
      const rb = Math.round(b.box[1] / 24);
      return ra !== rb ? ra - rb : a.box[0] - b.box[0];
    });

  for (const { dm, box } of ranked) {
    if (markId >= cfg.maxMarks) break;
    const named = await vault.tokenize(dm.name || '', cfg.kinds, extraRules);
    for (const t of named.tokens) piiFound.push(t);
    marks.push({
      id: ++markId,
      source: 'dom',
      role: dm.role || 'generic',
      name: named.text.slice(0, 140),
      editable: !!dm.editable,
      disabled: !!dm.disabled,
      checked: typeof dm.checked === 'boolean' ? dm.checked : null,
      redacted: merged.some((r) => {
        const inter = boxIntersect(r, box);
        return inter && boxArea(inter) / boxArea(box) > 0.5;
      }),
      bbox: devToEgress(box).map(Math.round),
      ref: { kind: 'dom', idx: dm.idx },
    });
  }

  // Canvas, video and cross-origin iframes have no DOM: mark OCR line clusters inside them.
  const opaque = Array.isArray(payload.opaque) ? payload.opaque : [];
  if (opaque.length && ocrWords.length && markId < cfg.maxMarks) {
    const opaqueBoxes = opaque.map((o) => normBox(...cssToDev(o.rect), 0, devW, devH));
    const lines = new Map();
    for (const w of ocrWords) {
      const wb = [w.bbox.x0 / ocrScale, w.bbox.y0 / ocrScale, w.bbox.x1 / ocrScale, w.bbox.y1 / ocrScale];
      if (!opaqueBoxes.some((ob) => boxIntersect(ob, wb))) continue;
      if (merged.some((r) => boxIntersect(r, wb))) continue; // never mark a redacted region
      if (w.confidence < cfg.ocrConfFloor) continue;
      const entry = lines.get(w.line);
      if (entry) {
        entry.box = [
          Math.min(entry.box[0], wb[0]), Math.min(entry.box[1], wb[1]),
          Math.max(entry.box[2], wb[2]), Math.max(entry.box[3], wb[3]),
        ];
        entry.text.push(w.text);
      } else {
        lines.set(w.line, { box: wb, text: [w.text] });
      }
    }
    for (const entry of lines.values()) {
      if (markId >= cfg.maxMarks) break;
      const box = normBox(...entry.box, 2, devW, devH);
      if (boxArea(box) < 240) continue;
      const named = await vault.tokenize(entry.text.join(' ').slice(0, 120), cfg.kinds, extraRules);
      marks.push({
        id: ++markId,
        source: 'vision',
        role: 'canvas-text',
        name: named.text,
        editable: false,
        disabled: false,
        checked: null,
        redacted: false,
        bbox: devToEgress(box).map(Math.round),
        // CSS rect is resolved here, where the empirical DPR lives, so the
        // executor never performs coordinate arithmetic of its own.
        ref: { kind: 'vision', css: devToCss(box) },
      });
    }
  }

  // Content-addressed ids so [14] names the same element on every frame of a
  // run. A one-off panel capture keeps plain reading-order numbers.
  if (track) RUN.ids.assign(marks);

  // OCR down: repaint the frame as a DOM wireframe with zero captured pixels.
  let mode = 'full';
  if (unsafe && cfg.failMode === 'wireframe') {
    mode = 'wireframe';
    egCtx.save();
    egCtx.fillStyle = PALETTE.wireBg;
    egCtx.fillRect(0, 0, egW, egH);
    egCtx.strokeStyle = PALETTE.wireStroke;
    egCtx.fillStyle = PALETTE.wireText;
    egCtx.lineWidth = 1;
    egCtx.textBaseline = 'middle';
    egCtx.font = '12px ui-sans-serif, system-ui, sans-serif';
    for (const m of marks) {
      const [x0, y0, x1, y1] = m.bbox;
      egCtx.strokeRect(x0 + 0.5, y0 + 0.5, Math.max(1, x1 - x0 - 1), Math.max(1, y1 - y0 - 1));
      const text = `${m.role}: ${m.name}`.slice(0, 80);
      if (x1 - x0 > 50 && y1 - y0 > 13) {
        egCtx.save();
        egCtx.beginPath();
        egCtx.rect(x0 + 3, y0, x1 - x0 - 6, y1 - y0);
        egCtx.clip();
        egCtx.fillText(text, x0 + 5, (y0 + y1) / 2);
        egCtx.restore();
      }
    }
    egCtx.fillStyle = PALETTE.redactionToken;
    egCtx.font = '700 13px ui-monospace, Menlo, monospace';
    egCtx.fillText('VEIL FALLBACK — SCHEMATIC ONLY, ZERO CAPTURED PIXELS', 12, 16);
    egCtx.restore();
  }

  const tm = performance.now();
  drawMarks(egCtx, marks, {
    width: egW,
    height: egH,
    fontSize: Math.max(11, Math.round(Math.min(egW, egH) / 62)),
    lineWidth: egW > 1100 ? 2 : 1.5,
  });
  timings.marks = Math.round(performance.now() - tm);

  const te = performance.now();
  const blob = await canvasToBlob(egressCanvas, 'image/png');
  const veiledDataUrl = await blobToDataUrl(blob);

  /* Delta: tiles are hashed on the FINAL egress pixels (marks included), so a
   * patch pasted into the server's keyframe reproduces this frame exactly. */
  let delta = { mode: 'full', reason: 'untracked', changeRatio: 1 };
  let egressBlob = blob;
  if (track) {
    const grid = AAVARAN_DELTA.tileGrid(egressCanvas);
    const diff = AAVARAN_DELTA.diffGrid(RUN.grid, grid);
    const pick = AAVARAN_DELTA.choose(diff, grid, {
      forceFull: !!payload.forceFull, stepsSinceKeyframe: RUN.sinceKeyframe,
    });
    delta = {
      mode: pick.mode, reason: pick.reason,
      changeRatio: Math.round(diff.ratio * 1e4) / 1e4, rect: pick.rect || null,
    };
    if (pick.mode === 'patch') {
      const [x, y, w, h] = pick.rect;
      const { canvas: crop, ctx: cropCtx } = makeCanvas(w, h);
      cropCtx.drawImage(egressCanvas, x, y, w, h, 0, 0, w, h);
      egressBlob = await canvasToBlob(crop, 'image/png');
    } else if (pick.mode === 'unchanged') {
      egressBlob = null;
    }
    RUN.grid = grid;
    RUN.sinceKeyframe = pick.mode === 'full' ? 0 : RUN.sinceKeyframe + 1;
  }
  // Exactly the image bytes that leave the machine this step (null: none).
  const egressDataUrl = egressBlob === blob ? veiledDataUrl
    : (egressBlob ? await blobToDataUrl(egressBlob) : null);
  timings.encode = Math.round(performance.now() - te);
  timings.total = Math.round(performance.now() - t0);

  // The URL and title leave the machine too; tokenize them like the pixels.
  const safeUrl = await vault.tokenize(String(vp.url || ''), cfg.kinds, extraRules);
  const safeTitle = await vault.tokenize(String(vp.title || ''), cfg.kinds, extraRules);
  for (const t of [...safeUrl.tokens, ...safeTitle.tokens]) piiFound.push(t);

  const seen = new Set();
  const pii = [];
  for (const p of piiFound) {
    const k = `${p.kind}|${p.token}`;
    if (seen.has(k)) continue;
    seen.add(k);
    pii.push(p);
  }

  return {
    ok: true,
    blocked: false,
    veiledDataUrl,
    egressDataUrl,
    delta: { ...delta, width: egW, height: egH },
    bytesRaw,
    bytesEgress: egressBlob ? egressBlob.size : 0,
    egress: { width: egW, height: egH, scale: egressScale },
    dpr: { x: dprX, y: dprY, offsetLeft: offL, offsetTop: offT },
    device: { width: devW, height: devH },
    // Text surfaces that leave the machine alongside the pixels. background.js
    // MUST forward these and never vp.url / vp.title, which are still raw.
    page: {
      url: safeUrl.text,
      title: safeTitle.text,
      urlTokenized: safeUrl.tokens.length > 0,
      titleTokenized: safeTitle.tokens.length > 0,
    },
    marks,
    pixelHash,
    markSignature: await markSignature(marks),
    newVaultEntries: vault.fresh,
    // Narrator only: raw visible text in reading order. Local to the extension;
    // background.js hands it to the panel and never into a request.
    localText: payload.narrate ? readingLines(ocrWords) : undefined,
    veil: {
      mode,
      ocrOk,
      faceOk,
      wordsScanned,
      textRegionsRedacted: textRegions,
      failClosedRegions,
      facesRedacted,
      profile: profile.name,
      redactionBoxes: merged.length,
      boxes: merged,   // device px; local only (the panel/bench), never sent
      pii,
      confidenceFloor: cfg.ocrConfFloor,
      timings,
    },
    warnings,
  };
}

const RUN = { sessionId: null, ids: null, grid: null, sinceKeyframe: 0, reuse: null };

let busy = false;

async function handleOffscreen(message) {
  switch (message.type) {
    case 'AAVARAN_PING':
      return {
        ok: true,
        ready: true,
        busy,
        ocr: { ready: !!OCR.worker, failed: OCR.failed, reason: OCR.failReason },
        face: { ready: FACE.loaded, backend: FACE.backend, failed: FACE.failed },
        ner: { ready: !!NER.pipe, device: NER.device, failed: NER.failed, reason: NER.reason },
      };

    case 'AAVARAN_PREFLIGHT': {
      const problems = await assertLocalAssets();
      return { ok: problems.length === 0, problems };
    }

    case 'AAVARAN_WARMUP': {
      const problems = await assertLocalAssets();
      if (problems.length) return { ok: false, problems, ocr: false, face: false, ner: false };
      // Independent engines: warm in parallel so one failure cannot cost the others.
      const [ocr, face, ner] = await Promise.allSettled([initOcr(), initFaces(), initNer()]);
      const result = {
        problems,
        ocr: ocr.status === 'fulfilled',
        face: face.status === 'fulfilled',
        ner: ner.status === 'fulfilled' && !!ner.value,
        nerDevice: NER.device,
      };
      if (ocr.status === 'rejected') result.ocrError = ocr.reason && ocr.reason.message;
      if (face.status === 'rejected') result.faceError = face.reason && face.reason.message;
      if (!result.ner) result.nerError = NER.reason;
      result.ok = result.ocr || result.face;
      return result;
    }

    case 'AAVARAN_VEIL':
      busy = true;
      try {
        return await veil(message.payload);
      } catch (e) {
        err('veil failed:', e);
        // Fail closed: no frame is produced, so background.js has nothing it
        // could accidentally transmit.
        return {
          ok: false, blocked: true, reason: 'veil_exception',
          error: e && e.message ? e.message : String(e),
          stack: e && e.stack ? String(e.stack).split('\n').slice(0, 4).join('\n') : null,
        };
      } finally {
        busy = false;
      }

    case 'AAVARAN_RELEASE':
      try { if (OCR.worker) await OCR.worker.terminate(); } catch { /* noop */ }
      OCR.worker = null;
      OCR.initPromise = null;
      return { ok: true };

    default:
      return undefined;
  }
}

self.AAVARAN_OFFSCREEN = handleOffscreen;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  // Only claim messages explicitly addressed here. runtime.sendMessage is a
  // broadcast: answering anything else races the service worker's own handler
  // and resolves the panel's request with the wrong payload.
  if (!message || message.target !== 'offscreen') return false;
  handleOffscreen(message).then(sendResponse);
  return true;
});

log('offscreen document live');
assertLocalAssets().then((problems) => {
  if (problems.length) {
    err(
      'LOCAL ASSET PREFLIGHT FAILED — redaction will not run:\n  ' + problems.join('\n  '),
    );
  }
});
