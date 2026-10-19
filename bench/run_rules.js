'use strict';
/* Text-channel benchmark: runs the extension's own PII rules (offscreen.js +
 * pii.hardening.js) over each bench page's visible text and writes
 * predictions.json for score.py. Measures the rule layer only — OCR geometry,
 * faces and IoU need the extension's Capture & Veil on the rendered page.
 *
 *   node bench/run_rules.js [bench/pages]
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ext = path.join(__dirname, '..', 'extension');
const quiet = { log() {}, warn() {}, error() {} };
const ctx = {
  console: quiet, TextEncoder, crypto: globalThis.crypto, performance,
  chrome: { runtime: { onMessage: { addListener() {} }, getURL: (p) => p } },
  fetch: () => Promise.reject(new Error('offline')),
};
ctx.self = ctx;
vm.createContext(ctx);
for (const f of ['pii.hardening.js', 'offscreen.js']) {
  vm.runInContext(fs.readFileSync(path.join(ext, f), 'utf8'), ctx, { filename: f });
}

const dir = process.argv[2] || path.join(__dirname, 'pages');
const labels = JSON.parse(fs.readFileSync(path.join(dir, 'labels.json'), 'utf8'));
const out = {};
for (const page of Object.keys(labels)) {
  const html = fs.readFileSync(path.join(dir, page), 'utf8');
  // Cells of one table row stay on one line, as the OCR re-lining renders them.
  const text = html.replace(/<style[\s\S]*?<\/style>/g, '')
    .replace(/<\/?span[^>]*>/g, '').replace(/<\/td>\s*<td>/g, ' | ').replace(/<[^>]+>/g, '\n');
  const t0 = performance.now();
  const spans = ctx.detectPiiSpans(text, null);
  out[page] = {
    pred: spans.map((s) => ({ kind: s.kind, value: s.raw })),
    latency_ms: performance.now() - t0,
  };
}
const file = path.join(dir, 'predictions.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1));
console.log(`wrote ${file}`);
