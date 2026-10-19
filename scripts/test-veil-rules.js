'use strict';
/* Regression tests for the veil engine's pure functions (no browser needed).
 *   node scripts/test-veil-rules.js */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ext = path.join(__dirname, '..', 'extension');
const ctx = {
  console: { log() {}, warn() {}, error() {} }, TextEncoder, crypto: globalThis.crypto, performance,
  chrome: { runtime: { onMessage: { addListener() {} }, getURL: (p) => p } },
  fetch: () => Promise.reject(new Error('offline')),
};
ctx.self = ctx;
vm.createContext(ctx);
for (const f of ['delta.js', 'offscreen.hardening.js', 'pii.hardening.js', 'offscreen.js']) {
  vm.runInContext(fs.readFileSync(path.join(ext, f), 'utf8'), ctx, { filename: f });
}
const run = (src) => vm.runInContext(src, ctx);
// Values from the vm realm have foreign prototypes; compare plain copies.
const local = (x) => JSON.parse(JSON.stringify(x));
const kinds = (text, extra) => local(ctx.detectPiiSpans(text, null, extra).map((s) => `${s.kind}:${s.raw}`));

// Checksum-gated identifiers and the fail-closed shapes.
assert.deepStrictEqual(kinds('Aadhaar 3456 7890 1238'), ['AADHAAR:3456 7890 1238']);
assert.deepStrictEqual(kinds('ref 1234 5678 9012'), ['GROUPED_ID:1234 5678 9012']);
assert.deepStrictEqual(kinds('card 5523 4444 5555 6669'), ['CARD:5523 4444 5555 6669']);
assert.deepStrictEqual(kinds('PAN | UJJPP76590'), ['PAN:UJJPP76590']);           // OCR O->0
assert.deepStrictEqual(kinds('UPI | arjuné6@paytm.'), ['UPI:arjuné6@paytm']);     // OCR é, sentence dot
assert.deepStrictEqual(kinds('mail meera43@example.in'), ['EMAIL:meera43@example.in']);
assert.deepStrictEqual(kinds('Name | Priya lyer'), ['NAME:Priya lyer']);          // OCR I->l
assert.deepStrictEqual(kinds('Name\nUPI'), []);                                   // never across lines
assert.deepStrictEqual(kinds('Submit  Download statement  Page 2 of 10'), []);

// NER pieces -> one regex that survives multi-word names (the \s rewrite bug).
const pats = run(`personPatterns([
  { entity: 'B-PERSON', score: 0.7, index: 4, word: 'arjun' },
  { entity: 'I-PERSON', score: 0.5, index: 5, word: 'reddy' },
  { entity: 'B-PERSON', score: 0.6, index: 9, word: 'ra' },
  { entity: 'B-PERSON', score: 0.8, index: 10, word: '##hul' },
])`);
assert.strictEqual(pats.length, 2);
const rule = { kind: 'NAME', re: new RegExp(`(?<![A-Za-z])(?:${pats.join('|')})(?:[ \\t]+[A-Zl][a-z]+)?(?![A-Za-z])`, 'g') };
assert.deepStrictEqual(kinds('Prepared for | Arjun Reddy', [rule]), ['NAME:Arjun Reddy']);
assert.deepStrictEqual(kinds('signed by Rahul Das today', [rule]), ['NAME:Rahul Das']);

// Two-column forms: Tesseract emits all labels, then all values. Re-lining
// must put each label next to its value.
const w = (text, x, y) => ({ text, bbox: { x0: x, y0: y, x1: x + 10 * text.length, y1: y + 16 }, confidence: 95 });
const words = run('relineWords')([w('Name', 60, 100), w('PAN', 60, 150), w('Meera', 330, 101), w('Reddy', 400, 101), w('ABCPD1234F', 330, 151)]);
const { text } = run('buildTextIndex')(words);
assert.strictEqual(text, 'Name | Meera Reddy\nPAN | ABCPD1234F');
assert.deepStrictEqual(kinds(text), ['NAME:Meera Reddy', 'PAN:ABCPD1234F']);

// Label proximity reaches the value right after "UPI " (off-by-one regression).
const fc = ctx.AAVARAN_HARDEN.failClosedBoxes(
  [{ ...w('UPI', 60, 100), line: 0 }, { ...w('x@y', 120, 100), line: 0, confidence: 99 }],
  { redactionPad: 0 }, ctx.AAVARAN_HARDEN.profileFor('https://example.com/'), 1, 2000, 2000, run('normBox'), new Set());
assert.deepStrictEqual(local(fc.reasons), ['label_proximity(UPI)']);

// Stable ids survive re-layout of other marks.
const ids = new ctx.AAVARAN_DELTA.StableMarkIds();
const a = ids.assign([{ role: 'button', name: 'Pay', bbox: [0, 0, 50, 20] }, { role: 'link', name: 'Help', bbox: [0, 40, 50, 60] }]);
const b = ids.assign([{ role: 'button', name: 'New', bbox: [0, 0, 50, 20] }, { role: 'link', name: 'Help', bbox: [0, 40, 50, 60] }]);
assert.strictEqual(a[1].id, b[1].id);
assert.notStrictEqual(a[0].id, b[0].id);

console.log('veil rule tests ok');
