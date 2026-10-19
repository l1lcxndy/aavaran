'use strict';
import './background.hardening.js';
/* ==========================================================================
 * AAVARAN — background.js  (MV3 service worker, type: "module")
 * ==========================================================================
 * The orchestrator. It owns four things nothing else may touch:
 *
 *   1. The offscreen document lifecycle (getContexts-guarded, race-free).
 *   2. The PII vault (IndexedDB). Plaintext enters here and leaves only into
 *      the page at execution time — never into a network call.
 *   3. The egress guard. Every outbound payload is scanned against the vault
 *      and against the raw PII patterns before fetch() is allowed to run.
 *   4. The ReAct driver: capture → veil → /act → execute → settle → repeat,
 *      with the server adjudicating whether each action actually changed the
 *      world before the next one is planned.
 *
 * All page interaction goes through chrome.scripting.executeScript into the
 * ISOLATED world. There is no persistent content script: nothing is injected
 * into a page until the user starts a run, which is both a smaller attack
 * surface and a smaller privacy claim to defend.
 * ========================================================================== */

/* ==========================================================================
 * 1. Configuration
 * ========================================================================== */

const DEFAULT_CONFIG = Object.freeze({
  serverUrl: 'http://localhost:8756',
  maxSteps: 25,
  stepTimeoutMs: 90_000,
  settleTimeoutMs: 4_000,
  settleQuietMs: 350,
  postCapturePaintMs: 120,
  purgeVaultOnSessionEnd: true,
  vaultTtlMs: 30 * 60 * 1000,
  veil: {
    egressMaxEdge: 1536,
    ocrMaxEdge: 3000,
    ocrConfFloor: 55,
    redactionPad: 4,
    maxMarks: 120,
    failMode: 'wireframe',     // 'wireframe' | 'block'
    enableFaces: true,
    enableOcr: true,
    labelRedactions: true,
  },
  collect: {
    maxCandidates: 400,
    includeCursorPointer: true,
    minSize: 8,
  },
  humanTyping: true,
  typingDelayMs: 12,
});

const OFFSCREEN_PATH = 'offscreen.html';
const CAPTURE_MIN_INTERVAL_MS = 520;   // captureVisibleTab is quota-limited
const EVENT_RING = 200;

const RESTRICTED = /^(chrome|edge|about|devtools|chrome-extension|chrome-untrusted|view-source):/i;
const WEBSTORE = /^https:\/\/(chromewebstore\.google\.com|chrome\.google\.com\/webstore)/i;

/* ==========================================================================
 * 2. Logging + the event bus the Glass Box panel renders
 * ========================================================================== */

const log = (...a) => console.log('[AAVARAN]', ...a);
const warn = (...a) => console.warn('[AAVARAN]', ...a);
const fail = (...a) => console.error('[AAVARAN]', ...a);

/** @type {object[]} */
let eventRing = [];

function emit(type, data = {}) {
  const event = { type, ts: Date.now(), ...data };
  // Frames are megabytes each: the ring keeps metadata, the live panel gets pixels.
  const { raw, veiled, ...slim } = event;
  eventRing.push(slim);
  if (eventRing.length > EVENT_RING) eventRing = eventRing.slice(-EVENT_RING);
  // The panel is a popup; it is usually closed. A rejected sendMessage here is
  // the normal case, not an error.
  chrome.runtime.sendMessage({ type: 'AAVARAN_EVENT', event }).catch(() => {});
  return event;
}

/* ==========================================================================
 * 3. Config store
 * ========================================================================== */

let configCache = null;

function deepMerge(base, patch) {
  if (!patch || typeof patch !== 'object') return base;
  const out = Array.isArray(base) ? base.slice() : { ...base };
  for (const [k, v] of Object.entries(patch)) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && base && typeof base[k] === 'object'
      ? deepMerge(base[k], v)
      : v;
  }
  return out;
}

async function getConfig() {
  if (configCache) return configCache;
  const stored = await chrome.storage.local.get('config');
  configCache = deepMerge(DEFAULT_CONFIG, stored.config || {});
  return configCache;
}

async function setConfig(patch) {
  const next = deepMerge(await getConfig(), patch);
  configCache = next;
  await chrome.storage.local.set({ config: next });
  emit('config', { config: next });
  return next;
}

/* ==========================================================================
 * 4. The vault — IndexedDB, local, never serialised outbound
 * ========================================================================== */

const VAULT_DB = 'aavaran-vault';
const VAULT_STORE = 'tokens';
let vaultDbPromise = null;

function openVault() {
  if (vaultDbPromise) return vaultDbPromise;
  vaultDbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(VAULT_DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        const store = db.createObjectStore(VAULT_STORE, { keyPath: 'hashKey' });
        store.createIndex('token', 'token', { unique: false });
        store.createIndex('sessionId', 'sessionId', { unique: false });
        store.createIndex('createdAt', 'createdAt', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return vaultDbPromise;
}

function vaultTx(mode, fn) {
  return openVault().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, mode);
    const store = tx.objectStore(VAULT_STORE);
    let result;
    try { result = fn(store); } catch (e) { reject(e); return; }
    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  }));
}

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/*
 * Plaintext is AES-GCM sealed at rest under a key that exists only in this
 * worker's memory. A copy of the profile directory yields ciphertext; a worker
 * restart makes old rows unreadable, so they are purged at boot.
 */
let vaultKeyPromise = null;

function vaultCryptoKey() {
  vaultKeyPromise = vaultKeyPromise
    || crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return vaultKeyPromise;
}

async function seal(value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, await vaultCryptoKey(), new TextEncoder().encode(String(value)));
  return { iv, ct };
}

async function unseal(row) {
  if (!row || !row.ct) return null;
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: row.iv }, await vaultCryptoKey(), row.ct);
    return new TextDecoder().decode(pt);
  } catch (e) {
    return null; // sealed under a previous worker's key
  }
}

async function vaultPut(entries, sessionId, origin) {
  if (!entries || !entries.length) return 0;
  const now = Date.now();
  // Encrypt first: an IndexedDB transaction auto-commits across an await.
  const rows = [];
  for (const e of entries) {
    rows.push({
      hashKey: e.hashKey,
      token: e.token,
      kind: e.kind,
      ...(await seal(e.value)),
      origin: origin || '',
      sessionId: sessionId || null,
      createdAt: now,
    });
  }
  await vaultTx('readwrite', (store) => { for (const r of rows) store.put(r); });
  return entries.length;
}

/** Rows with `value` decrypted. Only for the egress guard and rehydration. */
async function vaultPlain() {
  const rows = await vaultAll();
  return Promise.all(rows.map(async (r) => ({ ...r, value: await unseal(r) })));
}

async function vaultAll() {
  const db = await openVault();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, 'readonly');
    const req = tx.objectStore(VAULT_STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

/** vaultKey → token, replayed to offscreen so token numbering stays stable. */
async function vaultKnownTokens() {
  const rows = await vaultAll();
  const map = {};
  for (const r of rows) map[r.hashKey] = r.token;
  return map;
}

/** token → plaintext, for rehydration at the moment of execution. */
async function vaultResolve(token) {
  const db = await openVault();
  const tx = db.transaction(VAULT_STORE, 'readonly');
  const idx = tx.objectStore(VAULT_STORE).index('token');
  const row = await idbRequest(idx.get(token));
  return unseal(row);
}

async function vaultPurge({ sessionId = null, olderThanMs = null } = {}) {
  const rows = await vaultAll();
  const now = Date.now();
  const doomed = rows.filter((r) => {
    if (sessionId && r.sessionId === sessionId) return true;
    if (olderThanMs && now - r.createdAt > olderThanMs) return true;
    return !sessionId && !olderThanMs;
  });
  await vaultTx('readwrite', (store) => { for (const r of doomed) store.delete(r.hashKey); });
  emit('vault', { action: 'purge', removed: doomed.length, remaining: rows.length - doomed.length });
  return doomed.length;
}

/**
 * Substitute every <PII:KIND#n> token in a string with its plaintext.
 * This runs in the service worker, microseconds before the value is injected
 * into the page. The server produced the token; it never sees what replaced it.
 */
async function rehydrate(text) {
  if (typeof text !== 'string' || !text.includes('<PII:')) {
    return { text, rehydrated: [], missing: [] };
  }
  const tokens = [...new Set(text.match(/<PII:[A-Z_]+#\d+>/g) || [])];
  let out = text;
  const rehydrated = [];
  const missing = [];
  for (const token of tokens) {
    const value = await vaultResolve(token);
    if (value === null || value === undefined) { missing.push(token); continue; }
    out = out.split(token).join(value);
    rehydrated.push(token);
  }
  return { text: out, rehydrated, missing };
}

/* ==========================================================================
 * 5. Offscreen document lifecycle
 * ========================================================================== */

let offscreenCreating = null;

async function hasOffscreenDocument() {
  if (chrome.runtime.getContexts) {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [chrome.runtime.getURL(OFFSCREEN_PATH)],
    });
    return contexts.length > 0;
  }
  // Chrome < 116 has no getContexts; the service worker's own client list
  // is the only other way to see the offscreen document.
  const matched = await self.clients.matchAll();
  return matched.some((c) => c.url === chrome.runtime.getURL(OFFSCREEN_PATH));
}

/**
 * Chrome permits exactly one offscreen document per extension, and
 * createDocument() is not idempotent. Two concurrent captures both observing
 * "none exists" is the whole bug: the loser throws
 * "Only a single offscreen document may be created". The in-flight promise
 * serialises creation, and the error is still caught in case the document was
 * created by a path outside this function.
 */
async function ensureOffscreen() {
  // Firefox: no offscreen documents; the veil engine is loaded into this
  // background page itself (background.firefox.html) and called directly.
  if (self.AAVARAN_OFFSCREEN) return;
  if (await hasOffscreenDocument()) return;
  if (offscreenCreating) { await offscreenCreating; return; }

  offscreenCreating = chrome.offscreen.createDocument({
    url: OFFSCREEN_PATH,
    reasons: ['WORKERS', 'DOM_SCRAPING'],
    justification:
      'Run Tesseract and face detection on captured frames to destroy PII pixels locally before any egress.',
  }).catch(async (e) => {
    const msg = String(e && e.message ? e.message : e);
    if (/single offscreen|already exists|already an offscreen/i.test(msg)) return;
    throw e;
  }).finally(() => { offscreenCreating = null; });

  await offscreenCreating;

  // createDocument resolves on document load, which can precede offscreen.js
  // installing its listener. Handshake instead of assuming.
  for (let i = 0; i < 25; i++) {
    const pong = await sendToOffscreen({ type: 'AAVARAN_PING' }, 400).catch(() => null);
    if (pong && pong.ok) return;
    await sleep(80);
  }
  throw new Error('offscreen document did not become ready');
}

function sendToOffscreen(message, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`offscreen timeout after ${timeoutMs}ms (${message.type})`)),
      timeoutMs,
    );
    const reply = self.AAVARAN_OFFSCREEN
      ? self.AAVARAN_OFFSCREEN({ target: 'offscreen', ...message })
      : chrome.runtime.sendMessage({ target: 'offscreen', ...message });
    reply
      .then((r) => { clearTimeout(timer); resolve(r); })
      .catch((e) => { clearTimeout(timer); reject(e); });
  });
}

async function warmup() {
  await ensureOffscreen();
  const result = await sendToOffscreen({ type: 'AAVARAN_WARMUP' }, 180_000);
  if (!result || !result.ok) {
    fail('warmup failed:', result);
    emit('warmup', { ok: false, ...result });
  } else {
    emit('warmup', { ok: true, ocr: result.ocr, face: result.face, ner: result.ner, nerDevice: result.nerDevice });
  }
  return result;
}

/* ==========================================================================
 * 6. Capture
 * ========================================================================== */

let lastCaptureAt = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function assertCapturable(tab) {
  if (!tab) throw new Error('no active tab');
  const url = tab.url || tab.pendingUrl || '';
  if (!url) throw new Error('tab has no URL yet');
  if (RESTRICTED.test(url)) {
    throw new Error(`AAVARAN cannot operate on ${url.split(':')[0]}: pages (browser-restricted)`);
  }
  if (WEBSTORE.test(url)) throw new Error('AAVARAN cannot operate on the Chrome Web Store');
}

async function captureTab(tab) {
  const wait = CAPTURE_MIN_INTERVAL_MS - (Date.now() - lastCaptureAt);
  if (wait > 0) await sleep(wait);

  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
      lastCaptureAt = Date.now();
      if (!dataUrl || dataUrl.length < 512) throw new Error('capture returned an empty frame');
      return dataUrl;
    } catch (e) {
      lastError = e;
      // MAX_CAPTURE_VISIBLE_TAB_CALLS_PER_SECOND, or the tab was mid-paint.
      await sleep(400 * (attempt + 1));
    }
  }
  throw new Error(`captureVisibleTab failed: ${lastError && lastError.message}`);
}

/* ==========================================================================
 * 7. Injected page functions
 * --------------------------------------------------------------------------
 * These are serialised by chrome.scripting and evaluated in the page's
 * ISOLATED world. They close over nothing: every dependency is either a page
 * global or an entry in `args`. Element references live on the isolated
 * world's globalThis, so they survive between executeScript calls on the same
 * document and vanish on navigation — which is exactly the lifetime a mark
 * should have.
 * ========================================================================== */

function INJ_collect(cfg) {
  const NS = globalThis.__AAVARAN__ || (globalThis.__AAVARAN__ = { gen: 0, entries: [] });
  NS.gen = (NS.gen + 1) % 2147483647;
  NS.entries = [];

  const INTERACTIVE = [
    'a[href]', 'button', 'input:not([type="hidden"])', 'select', 'textarea',
    'summary', 'area[href]', 'label[for]',
    '[role="button"]', '[role="link"]', '[role="checkbox"]', '[role="radio"]',
    '[role="tab"]', '[role="menuitem"]', '[role="menuitemcheckbox"]',
    '[role="menuitemradio"]', '[role="combobox"]', '[role="switch"]',
    '[role="option"]', '[role="searchbox"]', '[role="textbox"]', '[role="slider"]',
    '[role="spinbutton"]', '[role="treeitem"]',
    '[contenteditable=""]', '[contenteditable="true"]',
    '[tabindex]:not([tabindex="-1"])',
    '[onclick]', '[data-testid][role]',
  ].join(',');

  // IMG included so the veil can fall back to destroying image regions when
  // the face model is down. SVG's tagName is lowercase in HTML documents.
  const OPAQUE_TAGS = new Set(['CANVAS', 'VIDEO', 'EMBED', 'OBJECT', 'SVG', 'IMG']);

  const vv = window.visualViewport;
  const viewport = {
    cssWidth: window.innerWidth,
    cssHeight: window.innerHeight,
    vvWidth: vv ? vv.width : window.innerWidth,
    vvHeight: vv ? vv.height : window.innerHeight,
    vvOffsetLeft: vv ? vv.offsetLeft : 0,
    vvOffsetTop: vv ? vv.offsetTop : 0,
    vvScale: vv ? vv.scale : 1,
    reportedDpr: window.devicePixelRatio,
    scrollX: window.scrollX,
    scrollY: window.scrollY,
    pageHeight: Math.max(
      document.documentElement ? document.documentElement.scrollHeight : 0,
      document.body ? document.body.scrollHeight : 0,
    ),
    url: location.href,
    origin: location.origin,
    title: document.title || '',
    readyState: document.readyState,
  };

  const vpBox = { x: 0, y: 0, w: viewport.vvWidth, h: viewport.vvHeight };

  function visible(el, style) {
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (Number(style.opacity) === 0) return false;
    if (el.hasAttribute && el.hasAttribute('inert')) return false;
    if (typeof el.checkVisibility === 'function') {
      try {
        if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
      } catch (e) { /* older Chrome signature */ }
    }
    return true;
  }

  function deepFromPoint(doc, x, y) {
    let node = doc.elementFromPoint(x, y);
    let guard = 0;
    while (node && node.shadowRoot && guard++ < 12) {
      const inner = node.shadowRoot.elementFromPoint(x, y);
      if (!inner || inner === node) break;
      node = inner;
    }
    return node;
  }

  function related(hit, target) {
    if (!hit) return false;
    if (hit === target) return true;
    if (target.contains(hit)) return true;
    let node = hit;
    for (let i = 0; i < 4 && node; i++) {
      if (node === target) return true;
      node = node.parentElement || (node.getRootNode && node.getRootNode().host) || null;
    }
    return false;
  }

  function accessibleName(el) {
    const bits = [];
    const push = (v) => { if (v && String(v).trim()) bits.push(String(v).trim()); };

    push(el.getAttribute && el.getAttribute('aria-label'));
    const labelledBy = el.getAttribute && el.getAttribute('aria-labelledby');
    if (labelledBy) {
      for (const id of labelledBy.split(/\s+/)) {
        const ref = el.ownerDocument.getElementById(id);
        if (ref) push(ref.textContent);
      }
    }
    if (el.labels && el.labels.length) for (const l of el.labels) push(l.textContent);
    push(el.getAttribute && el.getAttribute('placeholder'));
    push(el.getAttribute && el.getAttribute('alt'));
    push(el.getAttribute && el.getAttribute('title'));
    push(el.getAttribute && el.getAttribute('name'));
    if (el.tagName === 'SELECT' && el.selectedOptions && el.selectedOptions[0]) {
      push(el.selectedOptions[0].textContent);
    }
    if (!bits.length) {
      const text = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
      push(text.slice(0, 120));
    }
    if (!bits.length) push(el.getAttribute && el.getAttribute('data-testid'));
    return bits.join(' · ').replace(/\s+/g, ' ').trim().slice(0, 160);
  }

  function roleOf(el) {
    const explicit = el.getAttribute && el.getAttribute('role');
    if (explicit) return explicit.toLowerCase();
    const tag = el.tagName.toLowerCase();
    if (tag === 'a') return 'link';
    if (tag === 'button' || tag === 'summary') return 'button';
    if (tag === 'select') return 'combobox';
    if (tag === 'textarea') return 'textbox';
    if (tag === 'input') {
      const t = (el.type || 'text').toLowerCase();
      if (t === 'checkbox') return 'checkbox';
      if (t === 'radio') return 'radio';
      if (t === 'submit' || t === 'button' || t === 'reset' || t === 'image') return 'button';
      if (t === 'range') return 'slider';
      if (t === 'file') return 'file-input';
      return `textbox:${t}`;
    }
    if (el.isContentEditable) return 'textbox';
    return 'generic';
  }

  function isEditable(el) {
    if (el.isContentEditable) return true;
    const tag = el.tagName;
    if (tag === 'TEXTAREA') return true;
    if (tag !== 'INPUT') return false;
    const t = (el.type || 'text').toLowerCase();
    return !['checkbox', 'radio', 'submit', 'button', 'reset', 'image', 'file'].includes(t);
  }

  /**
   * Sensitivity is asserted from the DOM, not inferred from pixels. A password
   * renders as bullets: OCR has nothing to find, yet el.value is plaintext.
   */
  function sensitivity(el) {
    const tag = el.tagName;
    if (tag === 'INPUT' && (el.type || '').toLowerCase() === 'password') {
      return { sensitive: true, kind: 'PASSWORD' };
    }
    const ac = ((el.getAttribute && el.getAttribute('autocomplete')) || '').toLowerCase();
    if (/^cc-(number|csc|exp)/.test(ac)) return { sensitive: true, kind: 'CARD' };
    if (ac === 'tel' || ac === 'tel-national') return { sensitive: true, kind: 'PHONE' };
    if (ac === 'email') return { sensitive: true, kind: 'EMAIL' };
    if (ac === 'bday' || ac.startsWith('bday-')) return { sensitive: true, kind: 'DOB' };
    if (el.hasAttribute && el.hasAttribute('data-aavaran-sensitive')) {
      return { sensitive: true, kind: el.getAttribute('data-aavaran-sensitive').toUpperCase() || 'PASSWORD' };
    }
    return { sensitive: false, kind: null };
  }

  const candidates = [];
  const opaque = [];
  let cursorProbes = 0;

  function walk(root, doc, offX, offY, depth) {
    if (depth > 6) return;
    let all;
    try { all = root.querySelectorAll('*'); } catch (e) { return; }
    for (const el of all) {
      if (candidates.length > cfg.maxCandidates * 3) break;

      if (el.shadowRoot) walk(el.shadowRoot, doc, offX, offY, depth + 1);

      if (el.tagName === 'IFRAME' || el.tagName === 'FRAME') {
        const r = el.getBoundingClientRect();
        let inner = null;
        try { inner = el.contentDocument; } catch (e) { inner = null; }
        if (inner && inner.documentElement) {
          walk(inner.documentElement, inner, offX + r.left, offY + r.top, depth + 1);
        } else if (r.width > 20 && r.height > 20) {
          // Cross-origin: no DOM, so it becomes a vision-channel region.
          opaque.push({ kind: 'iframe-cross-origin', rect: { x: offX + r.left, y: offY + r.top, w: r.width, h: r.height } });
        }
        continue;
      }

      if (OPAQUE_TAGS.has(el.tagName.toUpperCase())) {
        const r = el.getBoundingClientRect();
        if (r.width > 40 && r.height > 40) {
          opaque.push({ kind: el.tagName.toLowerCase(), rect: { x: offX + r.left, y: offY + r.top, w: r.width, h: r.height } });
        }
      }

      let match = false;
      try { match = el.matches(INTERACTIVE); } catch (e) { match = false; }
      // getComputedStyle forces a style recalc, so it must never run over every
      // node on the page. Cheap structural filters first, and a hard probe
      // budget, keep inventory under ~40ms on a heavy document.
      if (!match && cfg.includeCursorPointer && el.children.length <= 3 && cursorProbes < 600) {
        cursorProbes++;
        try {
          if (getComputedStyle(el).cursor === 'pointer') match = true;
        } catch (e) { /* detached */ }
      }
      if (match) candidates.push({ el, doc, offX, offY });
    }
  }

  walk(document.documentElement, document, 0, 0, 0);

  const kept = [];
  for (const c of candidates) {
    const el = c.el;
    let style;
    try { style = getComputedStyle(el); } catch (e) { continue; }
    if (!visible(el, style)) continue;

    const local = el.getBoundingClientRect();
    if (local.width < cfg.minSize || local.height < cfg.minSize) continue;

    const rect = { x: c.offX + local.left, y: c.offY + local.top, w: local.width, h: local.height };
    // Only what is actually painted can be marked; captureVisibleTab has no
    // knowledge of anything outside the visual viewport.
    const vx0 = Math.max(rect.x, vpBox.x);
    const vy0 = Math.max(rect.y, vpBox.y);
    const vx1 = Math.min(rect.x + rect.w, vpBox.x + vpBox.w);
    const vy1 = Math.min(rect.y + rect.h, vpBox.y + vpBox.h);
    if (vx1 - vx0 < cfg.minSize || vy1 - vy0 < cfg.minSize) continue;
    if (rect.w * rect.h > vpBox.w * vpBox.h * 0.85) continue; // full-page wrappers

    // Occlusion: a mark the user cannot click is a mark the agent must not be
    // offered. Probe the centre and four inset corners in the element's own
    // document, in that document's coordinates.
    const cx = local.left + local.width / 2;
    const cy = local.top + local.height / 2;
    const inset = 3;
    const probes = [
      [cx, cy],
      [local.left + inset, local.top + inset],
      [local.right - inset, local.top + inset],
      [local.left + inset, local.bottom - inset],
      [local.right - inset, local.bottom - inset],
    ];
    let hitPoint = null;
    for (const [px, py] of probes) {
      if (px < 0 || py < 0) continue;
      const hit = deepFromPoint(c.doc, px, py);
      if (related(hit, el)) { hitPoint = { x: c.offX + px, y: c.offY + py }; break; }
    }
    if (!hitPoint) continue;

    const sens = sensitivity(el);
    const editable = isEditable(el);
    kept.push({
      el,
      rect,
      hitPoint,
      role: roleOf(el),
      name: accessibleName(el),
      value: editable ? String(el.value || (el.isContentEditable ? el.innerText : '') || '').slice(0, 256) : '',
      editable,
      disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
      checked: typeof el.checked === 'boolean' ? el.checked
        : (el.getAttribute('aria-checked') === 'true' ? true : null),
      sensitive: sens.sensitive,
      sensitiveKind: sens.kind,
      area: rect.w * rect.h,
      depth: (() => { let d = 0; let n = el; while (n && d < 64) { n = n.parentElement; d++; } return d; })(),
    });
  }

  // Deduplicate near-identical rects, keeping the innermost interactive node.
  kept.sort((a, b) => (a.area - b.area) || (b.depth - a.depth));
  const accepted = [];
  for (const k of kept) {
    const dupe = accepted.some((a) => {
      const ix = Math.max(0, Math.min(a.rect.x + a.rect.w, k.rect.x + k.rect.w) - Math.max(a.rect.x, k.rect.x));
      const iy = Math.max(0, Math.min(a.rect.y + a.rect.h, k.rect.y + k.rect.h) - Math.max(a.rect.y, k.rect.y));
      const inter = ix * iy;
      if (!inter) return false;
      const union = a.area + k.area - inter;
      return inter / union > 0.85;
    });
    if (!dupe) accepted.push(k);
    if (accepted.length >= cfg.maxCandidates) break;
  }

  accepted.sort((a, b) => {
    const ra = Math.round(a.rect.y / 24);
    const rb = Math.round(b.rect.y / 24);
    return ra !== rb ? ra - rb : a.rect.x - b.rect.x;
  });

  const marks = accepted.map((k, i) => {
    NS.entries.push({ el: k.el, doc: k.doc, hitPoint: k.hitPoint, rect: k.rect });
    return {
      idx: i,
      rect: k.rect,
      hitPoint: k.hitPoint,
      role: k.role,
      name: k.name,
      value: k.value,
      editable: k.editable,
      disabled: k.disabled,
      checked: k.checked,
      sensitive: k.sensitive,
      sensitiveKind: k.sensitiveKind,
    };
  });

  return { gen: NS.gen, viewport, marks, opaque: opaque.slice(0, 40) };
}

function INJ_act(job) {
  const NS = globalThis.__AAVARAN__;
  if (!NS) return { ok: false, error: 'no_inventory' };
  if (job.gen !== NS.gen) return { ok: false, error: 'stale_inventory', expected: NS.gen, got: job.gen };

  function scrollableAncestor(el) {
    let node = el;
    while (node && node !== document.body && node !== document.documentElement) {
      const st = getComputedStyle(node);
      if (/(auto|scroll|overlay)/.test(st.overflowY) && node.scrollHeight > node.clientHeight + 4) return node;
      node = node.parentElement;
    }
    return null;
  }

  function dispatchPointerSequence(el, x, y) {
    const base = {
      bubbles: true, cancelable: true, composed: true, view: window,
      clientX: x, clientY: y,
      screenX: Math.round(window.screenX + x),
      screenY: Math.round(window.screenY + y),
      button: 0, buttons: 1, detail: 1, isPrimary: true, pointerId: 1, pointerType: 'mouse',
    };
    const fire = (Ctor, type, extra) => {
      try { el.dispatchEvent(new Ctor(type, { ...base, ...extra })); } catch (e) { /* unsupported ctor */ }
    };
    fire(PointerEvent, 'pointerover', {});
    fire(MouseEvent, 'mouseover', {});
    fire(PointerEvent, 'pointermove', { buttons: 0 });
    fire(MouseEvent, 'mousemove', { buttons: 0 });
    fire(PointerEvent, 'pointerdown', {});
    fire(MouseEvent, 'mousedown', {});
    try { if (typeof el.focus === 'function') el.focus({ preventScroll: true }); } catch (e) { /* noop */ }
    fire(PointerEvent, 'pointerup', { buttons: 0 });
    fire(MouseEvent, 'mouseup', { buttons: 0 });
  }

  function nativelyActivatable(el) {
    const tag = el.tagName;
    if (['A', 'BUTTON', 'INPUT', 'SELECT', 'LABEL', 'SUMMARY', 'OPTION', 'AREA'].includes(tag)) return true;
    return !!(el.getAttribute && el.getAttribute('role'));
  }

  function setNativeValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    // React installs a value tracker that suppresses change events when the
    // value is written directly; resetting it is what makes controlled inputs
    // observe the write.
    if (el._valueTracker && typeof el._valueTracker.setValue === 'function') {
      el._valueTracker.setValue('');
    }
    if (desc && desc.set) desc.set.call(el, value); else el.value = value;
  }

  function keyEvent(el, type, key) {
    const map = {
      Enter: { code: 'Enter', keyCode: 13 },
      Tab: { code: 'Tab', keyCode: 9 },
      Escape: { code: 'Escape', keyCode: 27 },
      Backspace: { code: 'Backspace', keyCode: 8 },
      ArrowDown: { code: 'ArrowDown', keyCode: 40 },
      ArrowUp: { code: 'ArrowUp', keyCode: 38 },
      ArrowLeft: { code: 'ArrowLeft', keyCode: 37 },
      ArrowRight: { code: 'ArrowRight', keyCode: 39 },
      Delete: { code: 'Delete', keyCode: 46 },
      PageUp: { code: 'PageUp', keyCode: 33 },
      PageDown: { code: 'PageDown', keyCode: 34 },
      Home: { code: 'Home', keyCode: 36 },
      End: { code: 'End', keyCode: 35 },
    };
    const meta = map[key] || { code: `Key${key.toUpperCase()}`, keyCode: key.charCodeAt(0) };
    el.dispatchEvent(new KeyboardEvent(type, {
      key, code: meta.code, keyCode: meta.keyCode, which: meta.keyCode,
      bubbles: true, cancelable: true, composed: true,
    }));
  }

  function resolveTarget() {
    if (job.ref && job.ref.kind === 'dom') {
      const entry = NS.entries[job.ref.idx];
      if (!entry || !entry.el) return { error: 'mark_gone' };
      if (!entry.el.isConnected) return { error: 'mark_detached' };
      return { el: entry.el, doc: entry.doc || document };
    }
    if (job.ref && job.ref.kind === 'vision') {
      // Coordinates already converted from device px to CSS px by the veil
      // engine, which owns the empirical DPR. Nothing is re-scaled here.
      const x = job.ref.css.x + job.ref.css.w / 2;
      const y = job.ref.css.y + job.ref.css.h / 2;
      let node = document.elementFromPoint(x, y);
      let guard = 0;
      while (node && node.shadowRoot && guard++ < 12) {
        const inner = node.shadowRoot.elementFromPoint(x, y);
        if (!inner || inner === node) break;
        node = inner;
      }
      if (!node) return { error: 'no_element_at_point' };
      return { el: node, doc: document, point: { x, y } };
    }
    return { error: 'bad_ref' };
  }

  // The validator allows up/down/left/right/top/bottom; anything else was
  // previously treated as "down".
  function scrollBox(box) {
    const d = job.direction;
    const amount = job.amount || Math.round((box.clientHeight || window.innerHeight) * 0.85);
    const from = { x: box.scrollLeft, y: box.scrollTop };
    if (d === 'top') box.scrollTop = 0;
    else if (d === 'bottom') box.scrollTop = box.scrollHeight;
    else if (d === 'left' || d === 'right') box.scrollLeft += d === 'left' ? -amount : amount;
    else box.scrollTop += d === 'up' ? -amount : amount;
    return { ok: true, detail: { from, to: { x: box.scrollLeft, y: box.scrollTop } } };
  }

  const op = job.op;

  if (op === 'scroll' && !job.ref) {
    return scrollBox(document.scrollingElement || document.documentElement);
  }

  if (op === 'key' && !job.ref) {
    const el = document.activeElement || document.body;
    keyEvent(el, 'keydown', job.value || 'Enter');
    keyEvent(el, 'keyup', job.value || 'Enter');
    return { ok: true, detail: { key: job.value || 'Enter', on: el.tagName } };
  }

  const resolved = resolveTarget();
  if (resolved.error) return { ok: false, error: resolved.error };
  const el = resolved.el;

  // Re-measure now. The rect captured at perception time is already stale: the
  // page may have scrolled, a banner may have collapsed, a font may have
  // loaded. Acting on the captured rect is how agents click the wrong thing.
  // A mark inside a same-origin iframe measures in that frame's coordinates,
  // so hit-testing must use that frame's document and viewport, not the top's.
  const edoc = el.ownerDocument || document;
  const view = edoc.defaultView || window;
  let rect = el.getBoundingClientRect();
  const offscreenV =
    rect.bottom < 0 || rect.top > view.innerHeight ||
    rect.right < 0 || rect.left > view.innerWidth;
  if (offscreenV) {
    try { el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch (e) { /* noop */ }
    rect = el.getBoundingClientRect();
  }
  if (rect.width < 1 || rect.height < 1) return { ok: false, error: 'zero_size_target' };

  let px = Math.round(rect.left + rect.width / 2);
  let py = Math.round(rect.top + rect.height / 2);
  px = Math.max(1, Math.min(view.innerWidth - 2, px));
  py = Math.max(1, Math.min(view.innerHeight - 2, py));

  switch (op) {
    case 'click':
    case 'dblclick': {
      let hit = edoc.elementFromPoint(px, py);
      let guard = 0;
      while (hit && hit.shadowRoot && guard++ < 12) {
        const inner = hit.shadowRoot.elementFromPoint(px, py);
        if (!inner || inner === hit) break;
        hit = inner;
      }
      const ok = hit && (hit === el || el.contains(hit) || (hit.contains && hit.contains(el)));
      if (!ok) {
        // Something is on top — a cookie banner, a sticky header, a modal.
        // Report it rather than clicking whatever happens to be there.
        return {
          ok: false,
          error: 'occluded',
          detail: { occluderTag: hit ? hit.tagName : null, occluderClass: hit ? String(hit.className).slice(0, 80) : null },
        };
      }
      const clicks = op === 'dblclick' ? 2 : 1;
      for (let n = 1; n <= clicks; n++) {
        dispatchPointerSequence(el, px, py);
        if (nativelyActivatable(el) && typeof el.click === 'function') {
          el.click();
        } else {
          el.dispatchEvent(new MouseEvent('click', {
            bubbles: true, cancelable: true, composed: true, view,
            clientX: px, clientY: py, button: 0, detail: n,
          }));
        }
      }
      if (clicks === 2) {
        el.dispatchEvent(new MouseEvent('dblclick', {
          bubbles: true, cancelable: true, composed: true, view,
          clientX: px, clientY: py, button: 0, detail: 2,
        }));
      }
      return { ok: true, detail: { at: { x: px, y: py }, tag: el.tagName, clicks } };
    }

    case 'fill': {
      const value = String(job.value == null ? '' : job.value);
      try { el.focus({ preventScroll: true }); } catch (e) { /* noop */ }

      if (el.isContentEditable) {
        el.textContent = '';
        el.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
        el.textContent = value;
        el.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
        return { ok: true, detail: { chars: value.length, contentEditable: true } };
      }
      if (!('value' in el)) return { ok: false, error: 'not_fillable' };

      setNativeValue(el, '');
      el.dispatchEvent(new Event('input', { bubbles: true }));

      if (job.humanTyping && value.length <= 80) {
        // Autocomplete, search-as-you-type and validation-on-keystroke widgets
        // only react to per-character events.
        let acc = '';
        for (const ch of value) {
          acc += ch;
          keyEvent(el, 'keydown', ch);
          setNativeValue(el, acc);
          el.dispatchEvent(new InputEvent('input', { bubbles: true, data: ch, inputType: 'insertText' }));
          keyEvent(el, 'keyup', ch);
        }
      } else {
        setNativeValue(el, value);
        el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: value }));
      }
      el.dispatchEvent(new Event('change', { bubbles: true }));
      if (job.submit) {
        keyEvent(el, 'keydown', 'Enter');
        keyEvent(el, 'keyup', 'Enter');
        if (el.form && typeof el.form.requestSubmit === 'function') {
          try { el.form.requestSubmit(); } catch (e) { /* form may lack a submitter */ }
        }
      }
      return { ok: true, detail: { chars: value.length, submitted: !!job.submit } };
    }

    case 'select': {
      if (el.tagName !== 'SELECT') return { ok: false, error: 'not_a_select' };
      const want = String(job.value == null ? '' : job.value).trim().toLowerCase();
      let matched = -1;
      for (let i = 0; i < el.options.length; i++) {
        const o = el.options[i];
        if (o.value.toLowerCase() === want || o.textContent.trim().toLowerCase() === want) { matched = i; break; }
      }
      if (matched < 0) {
        for (let i = 0; i < el.options.length; i++) {
          if (el.options[i].textContent.trim().toLowerCase().includes(want)) { matched = i; break; }
        }
      }
      if (matched < 0) {
        return {
          ok: false,
          error: 'option_not_found',
          detail: { available: [...el.options].slice(0, 25).map((o) => o.textContent.trim()) },
        };
      }
      el.selectedIndex = matched;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      return { ok: true, detail: { selected: el.options[matched].textContent.trim() } };
    }

    case 'scroll':
      return scrollBox(scrollableAncestor(el) || document.scrollingElement || document.documentElement);

    case 'hover': {
      dispatchPointerSequence(el, px, py);
      return { ok: true, detail: { at: { x: px, y: py } } };
    }

    case 'key': {
      const key = job.value || 'Enter';
      try { el.focus({ preventScroll: true }); } catch (e) { /* noop */ }
      keyEvent(el, 'keydown', key);
      keyEvent(el, 'keyup', key);
      if (key === 'Enter' && el.form && typeof el.form.requestSubmit === 'function') {
        try { el.form.requestSubmit(); } catch (e) { /* form may lack a submitter */ }
      }
      return { ok: true, detail: { key } };
    }

    default:
      return { ok: false, error: `unsupported_op:${op}` };
  }
}

function INJ_settle(opts) {
  return new Promise((resolve) => {
    const start = Date.now();
    let quietTimer = null;
    let mutations = 0;

    const finish = (reason) => {
      try { observer.disconnect(); } catch (e) { /* noop */ }
      clearTimeout(hardStop);
      clearTimeout(quietTimer);
      resolve({ reason, ms: Date.now() - start, mutations, readyState: document.readyState });
    };

    const arm = () => {
      clearTimeout(quietTimer);
      quietTimer = setTimeout(() => {
        if (document.readyState === 'loading') { arm(); return; }
        finish('quiet');
      }, opts.quietMs);
    };

    const observer = new MutationObserver((records) => {
      mutations += records.length;
      arm();
    });
    observer.observe(document.documentElement, {
      childList: true, subtree: true, attributes: true, characterData: true,
    });

    const hardStop = setTimeout(() => finish('timeout'), opts.timeoutMs);
    arm();
  });
}

/* ==========================================================================
 * 8. Page operation wrappers
 * ========================================================================== */

async function runInPage(tabId, func, args, { world = 'ISOLATED' } = {}) {
  const results = await chrome.scripting.executeScript({
    target: { tabId },
    func,
    args,
    world,
    injectImmediately: true,
  });
  if (!results || !results.length) throw new Error('script injection returned nothing');
  const first = results[0];
  if (first.error) throw new Error(`page script error: ${first.error.message || first.error}`);
  return first.result;
}

async function collectInventory(tabId, cfg) {
  return runInPage(tabId, INJ_collect, [cfg.collect]);
}

async function executeAction(tabId, job) {
  return runInPage(tabId, INJ_act, [job]);
}

async function waitForSettle(tabId, cfg) {
  try {
    return await runInPage(tabId, INJ_settle, [
      { quietMs: cfg.settleQuietMs, timeoutMs: cfg.settleTimeoutMs },
    ]);
  } catch (e) {
    // A navigation can tear down the world mid-wait. That is a settle signal
    // in itself, not a failure.
    await sleep(cfg.settleQuietMs);
    return { reason: 'navigated', ms: cfg.settleQuietMs, mutations: 0 };
  }
}

async function waitForTabComplete(tabId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (!tab) throw new Error('tab closed');
    if (tab.status === 'complete') return tab;
    await sleep(120);
  }
  return chrome.tabs.get(tabId);
}

/* ==========================================================================
 * 9. The veil pipeline
 * ========================================================================== */

async function captureAndVeil(tab, cfg, { forceFull = false, narrate = false } = {}) {
  assertCapturable(tab);
  await ensureOffscreen();

  const t0 = Date.now();
  const inventory = await collectInventory(tab.id, cfg);
  const rawDataUrl = await captureTab(tab);
  await sleep(cfg.postCapturePaintMs);

  const knownTokens = await vaultKnownTokens();

  const result = await sendToOffscreen({
    type: 'AAVARAN_VEIL',
    payload: {
      rawDataUrl,
      domMarks: inventory.marks,
      opaque: inventory.opaque,
      viewport: inventory.viewport,
      knownTokens,
      config: cfg.veil,
      // Per-run delta chain and stable mark ids live in the veil engine.
      sessionId: currentRun.sessionId,
      forceFull,
      narrate,
    },
  });

  if (!result) throw new Error('offscreen returned no result');

  if (!result.ok) {
    // Fail closed. There is no degraded "send the raw frame" path: the raw
    // frame is precisely the thing this system exists to never transmit.
    emit('veil-blocked', { reason: result.reason, error: result.error, stack: result.stack });
    const e = new Error(`veil failed (${result.reason || 'unknown'}): ${result.error || ''}`);
    e.blocked = true;
    throw e;
  }

  if (result.newVaultEntries && result.newVaultEntries.length) {
    await vaultPut(result.newVaultEntries, currentRun.sessionId, inventory.viewport.origin);
  }

  for (const w of result.warnings || []) warn('veil warning:', w);

  const elapsed = Date.now() - t0;
  emit('veil', {
    ms: elapsed,
    mode: result.veil.mode,
    marks: result.marks.length,
    facesRedacted: result.veil.facesRedacted,
    textRegionsRedacted: result.veil.textRegionsRedacted,
    piiKinds: [...new Set(result.veil.pii.map((p) => p.kind))],
    bytesRaw: result.bytesRaw,
    bytesEgress: result.bytesEgress,
    timings: result.veil.timings,
  });

  return { rawDataUrl, inventory, ...result, ms: elapsed };
}

/* ==========================================================================
 * 10. The egress guard
 * --------------------------------------------------------------------------
 * The last line of defence, and the one that is actually auditable. Before any
 * fetch leaves this worker, the serialised payload is checked against every
 * plaintext value in the vault and against the raw PII patterns. A hit aborts
 * the request. This makes the privacy claim falsifiable instead of aspirational.
 * ========================================================================== */

const EGRESS_PATTERNS = [
  ['AADHAAR', /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/],
  ['PAN', /\b[A-Z]{5}\d{4}[A-Z]\b/],
  ['IFSC', /\b[A-Z]{4}0[A-Z\d]{6}\b/],
  ['EMAIL', /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b/],
  ['PHONE', /(?:\+?91[\s\-]?|\b0)?\b[6-9]\d{4}[\s\-]?\d{5}\b|(?:\+?91[\s\-]?|\b0)?\b[6-9]\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b/],
  ['CARD', /\b(?:\d[ \-]?){12,18}\d\b/],
];

// Machine-generated fields. No human text can reach them, so a digit run here
// is an artifact, not a leak. They are excluded from the *pattern* scan only —
// the vault-plaintext check below still covers the entire payload, including
// frame_png_b64, so a raw PII value baked into pixels-as-base64 would still
// be caught if it ever showed up there (it won't, since PNG bytes are binary,
// but this keeps the guard from special-casing away real coverage).
const OPAQUE_FIELDS = [
  'frame_png_b64', 'image', 'pixel_hash', 'pixelHash', 'session',
  'mark_signature', 'markSignature',
];

/** Best-effort: which top-level field contains this match, for the error. */
function fieldContaining(obj, needle) {
  for (const [k, v] of Object.entries(obj)) {
    try { if (JSON.stringify(v).includes(needle)) return k; } catch (e) { /* cyclic */ }
  }
  return '(payload)';
}

/** Show shape, not value: 5523 4444 5555 6669 -> 55##·####·####·#669 */
function maskMatch(s) {
  return s.length <= 6 ? '#'.repeat(s.length)
    : s.slice(0, 2) + '#'.repeat(s.length - 5) + s.slice(-3);
}

async function assertNoEgressLeak(payloadObject) {
  const serialised = JSON.stringify(payloadObject); // what is actually sent

  const probe = { ...payloadObject };
  for (const f of OPAQUE_FIELDS) delete probe[f];
  const scannable = JSON.stringify(probe);

  const rows = await vaultPlain();
  for (const row of rows) {
    if (!row.value || String(row.value).length < 4) continue;
    if (scannable.includes(row.value)) {
      throw Object.assign(
        new Error(`EGRESS BLOCKED: vault plaintext of kind ${row.kind} in field `
          + `${fieldContaining(probe, row.value)}`),
        { egressBlock: true, kind: row.kind },
      );
    }
  }
  for (const [kind, re] of EGRESS_PATTERNS) {
    re.lastIndex = 0;
    const m = re.exec(scannable);
    if (m) {
      throw Object.assign(
        new Error(`EGRESS BLOCKED: raw ${kind} in field `
          + `${fieldContaining(probe, m[0])} -> ${maskMatch(m[0])}`),
        { egressBlock: true, kind, field: fieldContaining(probe, m[0]) },
      );
    }
  }
  return serialised;
}

/* ==========================================================================
 * 11. Server client
 * ========================================================================== */

async function serverFetch(path, { method = 'POST', body = null, timeoutMs = 90_000, signal } = {}) {
  const cfg = await getConfig();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  if (signal) signal.addEventListener('abort', () => controller.abort(), { once: true });

  try {
    const res = await fetch(`${cfg.serverUrl.replace(/\/+$/, '')}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body || undefined,
      signal: controller.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON error body */ }
    if (!res.ok) {
      const detail = json && json.detail ? JSON.stringify(json.detail) : text.slice(0, 400);
      throw new Error(`server ${res.status}: ${detail}`);
    }
    return json;
  } finally {
    clearTimeout(timer);
  }
}

async function openServerSession(goal) {
  const body = await assertNoEgressLeak({ goal });
  const res = await serverFetch('/session', { body, timeoutMs: 15_000 });
  if (!res.signing_key) throw new Error('server issued no signing key; refusing an unsigned run');
  const raw = new Uint8Array(res.signing_key.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return { sessionId: res.session_id, key };
}

/**
 * Accept an action only if it carries this session's HMAC and names this
 * session and step. The action is read from the signed bytes, never from the
 * unsigned copy beside them.
 */
async function verifiedAction(decision, step) {
  const sig = String(decision.signature || '');
  if (!/^[0-9a-f]{64}$/.test(sig) || typeof decision.envelope !== 'string') {
    throw new Error('action is unsigned');
  }
  const ok = await crypto.subtle.verify(
    'HMAC', currentRun.signingKey,
    new Uint8Array(sig.match(/../g).map((h) => parseInt(h, 16))),
    new TextEncoder().encode(decision.envelope),
  );
  if (!ok) throw new Error('action signature is invalid');
  const env = JSON.parse(decision.envelope);
  if (env.session !== currentRun.sessionId || env.step !== step) {
    throw new Error(`signed action is for ${env.session}#${env.step}, not this step`);
  }
  return env.action;
}

/* The server's Observation schema (server/main.py) uses different field
   names than the extension's internal payload. Map here rather than
   renaming either side, since both names are meaningful in their own file. */
function toObservation(p) {
  const la = p.last_action;
  return {
    session: p.session_id,
    goal: p.goal,
    step: p.step,
    url: p.viewport.url,
    title: p.viewport.title,
    image: p.frame_png_b64,
    delta: p.delta,
    marks: p.marks,
    pixelHash: p.pixel_hash,
    markSignature: p.mark_signature,
    veil: {
      mode: p.veil.mode,
      ocr: !!p.veil.ocr_ok,
      faces: !!p.veil.face_ok,
      textRegions: p.veil.text_regions_redacted || 0,
      faceRegions: p.veil.faces_redacted || 0,
    },
    lastResult: la ? { ok: !!la.ok, error: la.error || null } : null,
  };
}

/* The server's action vocabulary (server/actions.py: type, index, text, ...)
 * does not match the executor's (op, mark_id, value, ...). Translate here
 * rather than in two places. `index` becomes `mark_id`, `type` (the field
 * name, distinct from the "type" action meaning "type text") becomes `op`.
 */
function mapServerAction(a) {
  if (!a) return null;
  const kind = a.type || a.action || '';
  const base = { reason: a.reason || a.summary || a.question || '' };
  switch (kind) {
    case 'click':
      return { ...base, op: 'click', mark_id: a.index };
    case 'double_click':
      return { ...base, op: 'dblclick', mark_id: a.index };
    case 'type':
      return { ...base, op: 'fill', mark_id: a.index, value: a.text, submit: !!a.submit };
    case 'clear':
      return { ...base, op: 'fill', mark_id: a.index, value: '' };
    case 'press_key':
      return { ...base, op: 'key', mark_id: a.index == null ? null : a.index, value: a.key };
    case 'select_option':
      return { ...base, op: 'select', mark_id: a.index, value: a.value };
    case 'scroll':
      return {
        ...base, op: 'scroll',
        mark_id: a.index == null ? null : a.index,
        direction: a.direction || 'down',
        amount: a.amount,
      };
    case 'hover':
      return { ...base, op: 'hover', mark_id: a.index };
    case 'navigate':
      return { ...base, op: 'navigate', value: a.url };
    case 'go_back':
      return { ...base, op: 'go_back' };
    case 'wait':
      return { ...base, op: 'wait', amount: a.ms };
    case 'extract':
      // No extraction sink exists yet on either side — the model's reasoning
      // text is already in the transcript and nothing separate consumes
      // `what`. Treat it as an immediate re-perceive rather than erroring.
      return { ...base, op: 'wait', amount: 0 };
    case 'ask_user':
      return { ...base, op: 'ask_user', reason: a.question || base.reason };
    case 'finish':
      return { ...base, op: 'done' };
    default:
      return { ...base, op: kind || 'unknown' };
  }
}

/** token -> { kind, origin } for one run. Never the value. */
async function vaultManifest(sessionId) {
  const vault = {};
  for (const r of await vaultAll()) {
    if (r.sessionId === sessionId) vault[r.token] = { kind: r.kind, origin: r.origin || '' };
  }
  return vault;
}

async function postAct(payload, signal) {
  // Token manifest: token -> kind + capture origin, never the value. Without it
  // the server rejects every type action that cites a token (unknown_token).
  const vault = await vaultManifest(payload.session_id);
  const body = await assertNoEgressLeak({ ...toObservation(payload), vault });
  emit('egress', { bytes: body.length, endpoint: '/act', step: payload.step });
  const cfg = await getConfig();
  return serverFetch('/act', { body, timeoutMs: cfg.stepTimeoutMs, signal });
}

async function closeServerSession(sessionId) {
  if (!sessionId) return;
  await serverFetch(`/session/${encodeURIComponent(sessionId)}/reset`, { timeoutMs: 8_000 })
    .catch((e) => warn('session close failed:', e.message));
}

/* ==========================================================================
 * 12. Keepalive
 * --------------------------------------------------------------------------
 * An MV3 service worker is evicted after ~30s without extension API activity.
 * A pending fetch does not count. This ticks a trivial API call so a long
 * multi-step run is not decapitated mid-loop.
 * ========================================================================== */

let keepaliveTimer = null;

function startKeepalive() {
  if (keepaliveTimer) return;
  keepaliveTimer = setInterval(() => {
    chrome.runtime.getPlatformInfo().catch(() => {});
  }, 20_000);
}

function stopKeepalive() {
  if (!keepaliveTimer) return;
  clearInterval(keepaliveTimer);
  keepaliveTimer = null;
}

/* ==========================================================================
 * 13. The ReAct driver
 * ========================================================================== */

const currentRun = {
  active: false,
  sessionId: null,
  goal: null,
  tabId: null,
  step: 0,
  startedAt: 0,
  abort: null,
  lastAction: null,
  lastFrame: null,
  bytesEgressed: 0,
  signingKey: null,
  piiDestroyed: 0,
};

function runSnapshot() {
  return {
    active: currentRun.active,
    sessionId: currentRun.sessionId,
    goal: currentRun.goal,
    tabId: currentRun.tabId,
    step: currentRun.step,
    startedAt: currentRun.startedAt,
    bytesEgressed: currentRun.bytesEgressed,
    piiDestroyed: currentRun.piiDestroyed,
    lastAction: currentRun.lastAction,
  };
}

function resetRun() {
  currentRun.active = false;
  currentRun.sessionId = null;
  currentRun.goal = null;
  currentRun.tabId = null;
  currentRun.step = 0;
  currentRun.abort = null;
  currentRun.lastAction = null;
  currentRun.lastFrame = null;
  currentRun.signingKey = null;
  stopKeepalive();
}

/**
 * Reason → Act → Observe.
 *
 * The client perceives and executes; the server reasons and, crucially,
 * adjudicates. Every request after the first carries the post-action frame
 * hash, so the server's first job on each turn is to decide whether the
 * previous action changed anything at all. A loop that does not check this
 * will cheerfully click a dead button twenty-five times and report success.
 */
async function runAgent({ goal, tabId }) {
  if (currentRun.active) throw new Error('a run is already in progress');

  const cfg = await getConfig();
  const abort = new AbortController();

  const tab = tabId
    ? await chrome.tabs.get(tabId)
    : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  assertCapturable(tab);

  currentRun.active = true;
  currentRun.goal = goal;
  currentRun.tabId = tab.id;
  currentRun.step = 0;
  currentRun.startedAt = Date.now();
  currentRun.abort = abort;
  currentRun.bytesEgressed = 0;
  currentRun.piiDestroyed = 0;
  startKeepalive();

  emit('run-start', { goal, tabId: tab.id, url: tab.url });

  let outcome = { status: 'stopped', reason: 'unknown' };

  try {
    ({ sessionId: currentRun.sessionId, key: currentRun.signingKey } = await openServerSession(goal));
    emit('session', { sessionId: currentRun.sessionId });

    // First frame of a run is always a keyframe; afterwards the server says when.
    let forceFull = true;
    let keyframeRetried = false;

    for (let step = 0; step < cfg.maxSteps; step++) {
      if (abort.signal.aborted) { outcome = { status: 'aborted', reason: 'user_stop' }; break; }
      currentRun.step = step;

      const liveTab = await chrome.tabs.get(tab.id);
      assertCapturable(liveTab);

      /* ---- perceive ---------------------------------------------------- */
      const frame = await captureAndVeil(liveTab, cfg, { forceFull });
      currentRun.lastFrame = {
        raw: frame.rawDataUrl,
        veiled: frame.veiledDataUrl,
        marks: frame.marks,
        veil: frame.veil,
      };
      currentRun.piiDestroyed +=
        frame.veil.textRegionsRedacted + frame.veil.facesRedacted;

      emit('frame', {
        step,
        raw: frame.rawDataUrl,
        veiled: frame.veiledDataUrl,
        bytesRaw: frame.bytesRaw,
        bytesEgress: frame.bytesEgress,
        marks: frame.marks.map((m) => ({
          id: m.id, role: m.role, name: m.name, source: m.source, redacted: m.redacted,
        })),
        veil: frame.veil,
      });

      /* ---- reason ------------------------------------------------------ */
      // ref carries live element handles; it is stripped here so the server is
      // structurally incapable of receiving anything but an index.
      const wireMarks = frame.marks.map(({ ref, ...rest }) => rest);

      const payload = {
        session_id: currentRun.sessionId,
        step,
        goal,
        // Only the delta crosses the wire: a full frame, a patch, or nothing.
        frame_png_b64: frame.egressDataUrl ? frame.egressDataUrl.split(',')[1] : null,
        delta: { ...frame.delta, frameId: `${currentRun.sessionId}:${step}` },
        viewport: {
          css_width: frame.inventory.viewport.cssWidth,
          css_height: frame.inventory.viewport.cssHeight,
          device_width: frame.device.width,
          device_height: frame.device.height,
          dpr: frame.dpr.x,
          egress_width: frame.egress.width,
          egress_height: frame.egress.height,
          egress_scale: frame.egress.scale,
          scroll_x: frame.inventory.viewport.scrollX,
          scroll_y: frame.inventory.viewport.scrollY,
          page_height: frame.inventory.viewport.pageHeight,
          // Tokenized by the veil, NOT frame.inventory.viewport.url/.title,
          // which are still raw. A path like /account/9876543210 or a title
          // reading "Statement — rahul@x.com" is a leak with no pixels in it,
          // and it is also exactly what trips the server's veil_check.
          url: frame.page ? frame.page.url : '',
          title: frame.page ? frame.page.title : '',
        },
        marks: wireMarks,
        veil: {
          mode: frame.veil.mode,
          ocr_ok: frame.veil.ocrOk,
          face_ok: frame.veil.faceOk,
          words_scanned: frame.veil.wordsScanned,
          text_regions_redacted: frame.veil.textRegionsRedacted,
          faces_redacted: frame.veil.facesRedacted,
          confidence_floor: frame.veil.confidenceFloor,
          pii: frame.veil.pii.map((p) => ({ token: p.token, kind: p.kind })),
          bytes_raw: frame.bytesRaw,
          bytes_egress: frame.bytesEgress,
        },
        pixel_hash: frame.pixelHash,
        mark_signature: frame.markSignature,
        last_action: currentRun.lastAction,
      };

      const decision = await postAct(payload, abort.signal);
      currentRun.bytesEgressed += frame.bytesEgress;

      // The server returns ok:false with action:null on a decode failure, an
      // unreachable VLM, or exhausted repair attempts. Reading .action.op
      // unconditionally is what turned that into a bare TypeError with no
      // indication of which of the three it was.
      forceFull = !!decision.needsKeyframe;
      if (!decision.ok) {
        // The server lost its base frame (restart, TTL): resend once as a keyframe.
        if (decision.needsKeyframe && !keyframeRetried) {
          keyframeRetried = true;
          step--;
          continue;
        }
        emit('decision', { step, action: null, error: decision.error || 'unknown_error' });
        outcome = { status: 'error', reason: decision.error || 'server returned ok:false' };
        break;
      }

      keyframeRetried = false;
      decision.action = await verifiedAction(decision, step);

      // Never execute on the server's say-so alone: re-validate against this
      // frame's manifest, the real URL, and the token origins.
      let check;
      try {
        check = self.AAVARAN_BG.validateAction(decision.action, wireMarks, {
          url: liveTab.url, vault: await vaultManifest(currentRun.sessionId),
        });
      } catch (e) {
        if (!(e instanceof self.AAVARAN_BG.ActionRejected)) throw e;
        currentRun.lastAction = {
          op: decision.action && decision.action.type, ok: false, error: `client_rejected: ${e.message}`,
        };
        emit('action', { step, ...currentRun.lastAction });
        continue; // the server sees the failure and re-plans
      }
      decision.requiresConfirmation = decision.requiresConfirmation || check.requiresConfirmation;
      decision.action = mapServerAction(decision.action);

      emit('decision', {
        step,
        action: decision.action,
        verification: decision.verification,
        reasoning: decision.reasoning,
        confidence: decision.confidence,
        degraded: decision.degraded,
      });

      // The validator flagged a destructive control (pay, transfer, delete…).
      // Execution stops here; a human completes or abandons it.
      if (decision.requiresConfirmation) {
        outcome = {
          status: 'needs_confirmation',
          reason: `${decision.action.op} [${decision.action.mark_id}] is ${decision.risk}-risk: ${decision.action.reason}`,
        };
        emit('confirm-required', { step, action: decision.action, risk: decision.risk });
        break;
      }
      if (decision.action.op === 'ask_user') {
        outcome = { status: 'needs_user', reason: decision.action.reason || 'the agent needs input' };
        break;
      }
      if (decision.action.op === 'done' || decision.done) {
        outcome = { status: 'done', reason: decision.action.reason || 'goal reached' };
        break;
      }
      if (decision.action.op === 'stop') {
        outcome = { status: 'stopped', reason: decision.action.reason || 'server halted the run' };
        break;
      }

      /* ---- act --------------------------------------------------------- */
      let job = {
        gen: frame.inventory.gen,
        op: decision.action.op,
        value: decision.action.value == null ? null : String(decision.action.value),
        direction: decision.action.direction || 'down',
        amount: decision.action.amount || null,
        submit: !!decision.action.submit,
        humanTyping: cfg.humanTyping,
        ref: null,
      };

      if (decision.action.mark_id != null) {
        const mark = frame.marks.find((m) => m.id === decision.action.mark_id);
        if (!mark) {
          currentRun.lastAction = {
            op: job.op, mark_id: decision.action.mark_id, ok: false,
            error: 'mark_id_not_in_manifest',
          };
          emit('action', currentRun.lastAction);
          continue; // the server will see the failure and re-plan
        }
        job.ref = mark.ref;
        job.markName = mark.name;
      }

      // Rehydrate at the last possible instant. The plaintext exists in this
      // worker for the duration of one executeScript call and is never written
      // anywhere that a network call can read.
      let rehydratedTokens = [];
      if (job.value) {
        const r = await rehydrate(job.value);
        job.value = r.text;
        rehydratedTokens = r.rehydrated;
        if (r.missing.length) {
          warn('unresolvable tokens:', r.missing);
        }
      }

      let execResult;
      if (job.op === 'navigate') {
        await chrome.tabs.update(tab.id, { url: job.value });
        await waitForTabComplete(tab.id, cfg.settleTimeoutMs + 6_000);
        execResult = { ok: true, detail: { navigated: true } };
      } else if (job.op === 'go_back') {
        await runInPage(tab.id, () => { history.back(); }, []);
        await waitForTabComplete(tab.id, cfg.settleTimeoutMs + 6_000);
        execResult = { ok: true, detail: { wentBack: true } };
      } else if (job.op === 'wait') {
        await sleep(Math.min(5_000, Number(job.amount) || 1_000));
        execResult = { ok: true, detail: { waited: true } };
      } else {
        execResult = await executeAction(tab.id, job).catch((e) => ({ ok: false, error: e.message }));
      }

      currentRun.lastAction = {
        op: job.op,
        mark_id: decision.action.mark_id == null ? null : decision.action.mark_id,
        mark_name: job.markName || null,
        // The tokens are reported; the values they stood for are not.
        rehydrated: rehydratedTokens,
        ok: !!execResult.ok,
        error: execResult.error || null,
        detail: execResult.detail || null,
      };
      emit('action', { step, ...currentRun.lastAction });

      /* ---- observe ----------------------------------------------------- */
      await waitForSettle(tab.id, cfg);
      await waitForTabComplete(tab.id, cfg.settleTimeoutMs).catch(() => {});
    }

    if (currentRun.step >= cfg.maxSteps - 1 && outcome.status === 'stopped' && outcome.reason === 'unknown') {
      outcome = { status: 'exhausted', reason: `step budget of ${cfg.maxSteps} exhausted` };
    }
  } catch (e) {
    fail('run failed:', e);
    outcome = {
      status: e.egressBlock ? 'egress_blocked' : (e.blocked ? 'veil_blocked' : 'error'),
      reason: e.message,
    };
    emit('run-error', { status: outcome.status, error: e.message });
  } finally {
    const sessionId = currentRun.sessionId;
    emit('run-end', { ...outcome, ...runSnapshot(), durationMs: Date.now() - currentRun.startedAt });
    await closeServerSession(sessionId);
    if (cfg.purgeVaultOnSessionEnd) await vaultPurge({ sessionId });
    resetRun();
  }

  return outcome;
}

/* ==========================================================================
 * 14. Message router
 * ========================================================================== */

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  // Messages addressed to the offscreen document also reach this listener;
  // claiming them here would resolve the sender's promise with the wrong value.
  if (!message || message.target === 'offscreen') return false;

  const handlers = {
    async AAVARAN_STATE() {
      const cfg = await getConfig();
      let offscreen = null;
      try {
        await ensureOffscreen();
        offscreen = await sendToOffscreen({ type: 'AAVARAN_PING' }, 3_000);
      } catch (e) {
        offscreen = { ok: false, error: e.message };
      }
      return { ok: true, run: runSnapshot(), config: cfg, offscreen, events: eventRing.slice(-40) };
    },

    async AAVARAN_PREFLIGHT() {
      await ensureOffscreen();
      const assets = await sendToOffscreen({ type: 'AAVARAN_PREFLIGHT' }, 20_000);
      let server = { reachable: false };
      try {
        const health = await serverFetch('/healthz', { method: 'GET', timeoutMs: 4_000 });
        server = { reachable: true, ...health };
      } catch (e) {
        server = { reachable: false, error: e.message };
      }
      return { ok: assets.ok, assets, server };
    },

    async AAVARAN_WARMUP() {
      return warmup();
    },

    // Accessibility narrator: the same local perception pass, read aloud by
    // the panel. OCR lines cover canvas and broken markup that screen readers
    // miss; the controls come from the DOM. Raw text stays in the extension.
    async AAVARAN_NARRATE() {
      const cfg = await getConfig();
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const frame = await captureAndVeil(tab, cfg, { narrate: true });
      return {
        ok: true,
        title: frame.inventory.viewport.title,
        lines: frame.localText || [],
        controls: frame.inventory.marks.map((m) => ({
          role: m.role, name: m.sensitive ? `${m.name} (sensitive)` : m.name, disabled: m.disabled,
        })),
      };
    },

    async AAVARAN_CAPTURE() {
      const cfg = await getConfig();
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const frame = await captureAndVeil(tab, cfg);
      return {
        ok: true,
        raw: frame.rawDataUrl,
        veiled: frame.veiledDataUrl,
        marks: frame.marks.map(({ ref, ...rest }) => rest),
        veil: frame.veil,
        bytesRaw: frame.bytesRaw,
        bytesEgress: frame.bytesEgress,
        pixelHash: frame.pixelHash,
        ms: frame.ms,
      };
    },

    async AAVARAN_RUN() {
      if (!message.goal || !String(message.goal).trim()) throw new Error('goal is required');
      // Deliberately not awaited: the loop outlives the popup that started it.
      runAgent({ goal: String(message.goal).trim(), tabId: message.tabId }).catch(() => {});
      return { ok: true, started: true };
    },

    async AAVARAN_STOP() {
      if (!currentRun.active) return { ok: true, wasActive: false };
      currentRun.abort.abort();
      return { ok: true, wasActive: true };
    },

    async AAVARAN_CONFIG() {
      if (message.patch) return { ok: true, config: await setConfig(message.patch) };
      return { ok: true, config: await getConfig() };
    },

    async AAVARAN_VAULT() {
      if (message.action === 'purge') {
        return { ok: true, removed: await vaultPurge(message.filter || {}) };
      }
      const rows = await vaultAll();
      // Token and kind only. The panel is a UI surface; plaintext has no
      // business being rendered into one.
      return {
        ok: true,
        entries: rows.map((r) => ({
          token: r.token, kind: r.kind, createdAt: r.createdAt,
          // UTF-8 length from the ciphertext (minus the 16-byte GCM tag); no decrypt needed.
          sessionId: r.sessionId, valueLength: r.ct ? r.ct.byteLength - 16 : 0,
        })),
      };
    },

    async AAVARAN_EVENTS() {
      return { ok: true, events: eventRing.slice(-(message.limit || 100)) };
    },
  };

  const handler = handlers[message.type];
  if (!handler) return false;

  handler()
    .then((r) => sendResponse(r))
    .catch((e) => {
      fail(`${message.type} failed:`, e);
      sendResponse({ ok: false, error: e && e.message ? e.message : String(e), blocked: !!e.blocked });
    });
  return true;
});

/* ==========================================================================
 * 15. Lifecycle
 * ========================================================================== */

chrome.runtime.onInstalled.addListener(async (details) => {
  log(`installed (${details.reason})`);
  await getConfig();
  try {
    const result = await warmup();
    if (result && result.problems && result.problems.length) {
      fail('ASSET PREFLIGHT FAILED:\n  ' + result.problems.join('\n  '));
    }
  } catch (e) {
    warn('warmup on install failed:', e.message);
  }
  await vaultPurge({ olderThanMs: DEFAULT_CONFIG.vaultTtlMs });
});

chrome.runtime.onStartup.addListener(async () => {
  // A vault entry that outlives its run is a liability with no upside.
  const cfg = await getConfig();
  await vaultPurge({ olderThanMs: cfg.vaultTtlMs });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (currentRun.active && currentRun.tabId === tabId && currentRun.abort) {
    warn('target tab closed, aborting run');
    currentRun.abort.abort();
  }
});

// The vault key was born with this worker, so every existing row is sealed
// under a key that no longer exists.
vaultPurge().catch((e) => warn('boot vault purge failed:', e.message));

log('service worker live');
