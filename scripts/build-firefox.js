'use strict';
/* Build the Firefox variant into dist/firefox from the same sources.
 *   node scripts/build-firefox.js
 * Then load dist/firefox/manifest.json via about:debugging → This Firefox.
 * The manifest is derived from extension/manifest.json so the two cannot drift. */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const src = path.join(root, 'extension');
const out = path.join(root, 'dist', 'firefox');

fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(src, out, { recursive: true });

const m = JSON.parse(fs.readFileSync(path.join(src, 'manifest.json'), 'utf8'));
delete m.minimum_chrome_version;
m.permissions = m.permissions.filter((p) => p !== 'offscreen');
// Event page instead of a service worker: it has the DOM the veil engine needs.
m.background = { page: 'background.firefox.html' };
m.browser_specific_settings = {
  gecko: { id: 'aavaran@sih26171.example', strict_min_version: '128.0' },  // world: ISOLATED in scripting
};
fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(m, null, 2) + '\n');
fs.rmSync(path.join(out, 'offscreen.html'));
console.log(`built ${out}`);
