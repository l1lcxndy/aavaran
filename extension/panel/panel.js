/* ==========================================================================
 * AAVARAN — Glass Box panel
 * --------------------------------------------------------------------------
 * This is a pure view. It holds no pixels of its own, performs no redaction,
 * and never renders a vault plaintext — the background worker only ever hands
 * it token strings. Its whole job is to make the privacy claim *visible*: raw
 * frame on the left, the frame that actually left the machine on the right,
 * and a byte counter proving those are not the same image.
 *
 * Message contract (background.js section 14):
 *   AAVARAN_STATE  AAVARAN_PREFLIGHT  AAVARAN_WARMUP  AAVARAN_CAPTURE
 *   AAVARAN_RUN    AAVARAN_STOP       AAVARAN_CONFIG  AAVARAN_VAULT
 *   AAVARAN_EVENTS
 * Inbound broadcast: { type: 'AAVARAN_EVENT', event }
 * ========================================================================== */

'use strict';

const $ = (id) => document.getElementById(id);

const el = {
  banner: $('banner'),
  goal: $('goal'),
  btnRun: $('btnRun'),
  btnStop: $('btnStop'),
  btnCapture: $('btnCapture'),
  btnPreflight: $('btnPreflight'),
  btnVault: $('btnVault'),
  btnPurge: $('btnPurge'),
  btnNarrate: $('btnNarrate'),
  runState: $('runState'),
  imgRaw: $('imgRaw'),
  imgVeil: $('imgVeil'),
  tagRaw: $('tagRaw'),
  tagVeil: $('tagVeil'),
  stats: $('stats'),
  tokens: $('tokens'),
  log: $('log'),
  dOcr: $('dOcr'),
  dFace: $('dFace'),
  dSrv: $('dSrv'),
};

/* --------------------------------------------------------------------------
 * Transport
 * --------------------------------------------------------------------------
 * sendMessage rejects when the service worker is asleep or mid-restart. That
 * is routine in MV3, not an error worth a red line in the trace, so it is
 * retried once before it is reported.
 * -------------------------------------------------------------------------- */
async function send(type, extra = {}, retry = true) {
  try {
    const res = await chrome.runtime.sendMessage({ type, ...extra });
    if (res && res.ok === false) throw Object.assign(new Error(res.error || type + ' failed'), { blocked: res.blocked });
    return res;
  } catch (e) {
    if (retry && /message port closed|Receiving end does not exist/i.test(e.message || '')) {
      await new Promise((r) => setTimeout(r, 250));
      return send(type, extra, false);
    }
    throw e;
  }
}

/* -------------------------------------------------------------------------- */

function fmtBytes(n) {
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

function logLine(kind, text, isErr) {
  const row = document.createElement('div');
  if (isErr) row.className = 'err';
  const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
  row.innerHTML = `<span class="t">${t}</span><span class="k">${kind}</span> `;
  row.appendChild(document.createTextNode(text));
  el.log.appendChild(row);
  while (el.log.childElementCount > 300) el.log.removeChild(el.log.firstChild);
  el.log.scrollTop = el.log.scrollHeight;
}

function banner(title, body) {
  if (!title) { el.banner.classList.remove('show'); return; }
  el.banner.innerHTML = '';
  const b = document.createElement('b');
  b.textContent = title;
  el.banner.appendChild(b);
  const p = document.createElement('div');
  p.textContent = body || '';
  el.banner.appendChild(p);
  el.banner.classList.add('show');
}

function dot(node, state) {
  node.className = 'dot' + (state ? ' ' + state : '');
}

function chips(items) {
  el.stats.innerHTML = '';
  for (const [label, value, tone] of items) {
    const c = document.createElement('span');
    c.className = 'chip' + (tone ? ' ' + tone : '');
    c.innerHTML = `${label} <b></b>`;
    c.querySelector('b').textContent = String(value);
    el.stats.appendChild(c);
  }
}

/* --------------------------------------------------------------------------
 * Event stream
 * -------------------------------------------------------------------------- */

const EVENT_TEXT = {
  'run-start': (e) => `goal: ${e.goal || ''}`,
  'run-end': (e) => `${e.status || 'ended'} after ${(e.step ?? -1) + 1} steps, ${fmtBytes(e.bytesEgressed)} egressed` +
    (e.reason ? ` · ${e.reason}` : ''),
  'frame': (e) => `step ${e.step} · ${(e.marks || []).length} marks · ${fmtBytes(e.bytesRaw)} → ${fmtBytes(e.bytesEgress)}`,
  'confirm-required': (e) => `HALTED for human confirmation: ${e.action ? e.action.op : ''} [${e.action ? e.action.mark_id : ''}]`,
  'veil': (e) =>
    `${e.mode} · ${e.marks} marks · ${e.textRegionsRedacted} text + ${e.facesRedacted} face regions destroyed · ` +
    `${fmtBytes(e.bytesRaw)} → ${fmtBytes(e.bytesEgress)} · ${e.ms}ms` +
    (e.piiKinds && e.piiKinds.length ? ` · ${e.piiKinds.join(',')}` : ''),
  'veil-blocked': (e) => `FAIL-CLOSED: ${e.reason || 'unknown'} ${e.error || ''}`,
  'egress': (e) => `${e.endpoint} step ${e.step} · ${fmtBytes(e.bytes)}`,
  'egress-blocked': (e) => `EGRESS BLOCKED: ${e.reason || e.error || ''}`,
  'decision': (e) =>
    `${e.action ? e.action.op : '?'}` +
    (e.action && e.action.mark_id != null ? ` [${e.action.mark_id}]` : '') +
    (e.verification ? ` · verdict=${e.verification.verdict}` : '') +
    (e.reasoning ? ` · ${e.reasoning}` : ''),
  'action': (e) => `${e.op || ''} ${e.ok === false ? 'FAILED: ' + (e.error || '') : 'ok'}`,
  'settle': (e) => `${e.reason || ''} ${e.ms ?? ''}ms`,
  'vault': (e) => `${e.added ?? 0} added, ${e.removed ?? 0} removed`,
};

// refreshState() replays the ring every 2s; only render what is new.
const seenEvents = new Set();

function renderEvent(ev) {
  const key = `${ev.ts}|${ev.type}|${ev.step ?? ''}`;
  if (seenEvents.has(key)) return;
  seenEvents.add(key);
  // Live frames carry pixels (the ring copy does not): keep the Glass Box current mid-run.
  if (ev.type === 'frame' && ev.raw && ev.veiled) {
    el.imgRaw.src = ev.raw;
    el.imgVeil.src = ev.veiled;
    el.tagRaw.textContent = fmtBytes(ev.bytesRaw);
    el.tagVeil.textContent = `${fmtBytes(ev.bytesEgress)} · ${(ev.marks || []).length} marks`;
  }
  const fmt = EVENT_TEXT[ev.type];
  const isErr = /blocked|error|fail/i.test(ev.type) || ev.ok === false;
  let text;
  try {
    text = fmt ? fmt(ev) : JSON.stringify(ev, (k, v) => (k === 'type' || k === 'ts' ? undefined : v));
  } catch {
    text = '';
  }
  logLine(ev.type, text || '', isErr);

  if (ev.type === 'run-start') setRunning(true);
  if (ev.type === 'run-end') { setRunning(false); refreshVault().catch(() => {}); }
  if (ev.type === 'veil-blocked') {
    banner('Veil failed — nothing was transmitted',
      'The agent refused to send the frame rather than send it unredacted. See the trace below.');
  }
  if (ev.type === 'confirm-required') {
    banner('Stopped before a high-risk action',
      'The agent proposed a payment/transfer/delete-type action. Nothing was clicked — complete it yourself if intended.');
  }
  if (ev.type === 'egress-blocked') {
    banner('Egress guard tripped', 'A raw identifier was found in the outbound payload and the request was aborted.');
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === 'AAVARAN_EVENT' && msg.event) renderEvent(msg.event);
  return false;
});

/* --------------------------------------------------------------------------
 * State
 * -------------------------------------------------------------------------- */

function setRunning(active) {
  el.btnRun.disabled = active;
  el.btnStop.disabled = !active;
  el.btnCapture.disabled = active;
  el.btnNarrate.disabled = active;
  el.runState.textContent = active ? 'running' : 'idle';
}

async function refreshState() {
  const s = await send('AAVARAN_STATE');
  const off = s.offscreen || {};
  dot(el.dOcr, off.ocr && off.ocr.ready ? 'ok' : (off.ocr && off.ocr.failed ? 'bad' : 'warn'));
  dot(el.dFace, off.face && off.face.ready ? 'ok' : (off.face && off.face.failed ? 'bad' : 'warn'));
  if (off.ocr && off.ocr.failed && off.ocr.reason) {
    banner('OCR is not available — the veil cannot run', off.ocr.reason);
  }
  setRunning(!!(s.run && s.run.active));
  if (s.run && s.run.active) {
    el.runState.textContent = `running · step ${s.run.step} · ${fmtBytes(s.run.bytesEgressed)} out`;
    if (s.run.goal && !el.goal.value) el.goal.value = s.run.goal;
  }
  for (const ev of s.events || []) renderEvent(ev);
  return s;
}

async function refreshVault() {
  const v = await send('AAVARAN_VAULT');
  el.tokens.innerHTML = '';
  if (!v.entries || !v.entries.length) {
    el.tokens.innerHTML = '<span class="empty">nothing tokenized yet</span>';
    return;
  }
  for (const e of v.entries) {
    const s = document.createElement('span');
    s.className = 'tok';
    s.textContent = e.token;
    s.title = `${e.kind} · ${e.valueLength} chars held locally · never transmitted`;
    el.tokens.appendChild(s);
  }
}

/* --------------------------------------------------------------------------
 * Actions
 * -------------------------------------------------------------------------- */

async function doCapture() {
  banner(null);
  el.btnCapture.disabled = true;
  el.tagRaw.textContent = 'capturing…';
  el.tagVeil.textContent = '';
  try {
    const r = await send('AAVARAN_CAPTURE');
    el.imgRaw.src = r.raw;
    el.imgVeil.src = r.veiled;
    el.tagRaw.textContent = fmtBytes(r.bytesRaw);
    el.tagVeil.textContent = `${fmtBytes(r.bytesEgress)} · ${r.marks.length} marks`;
    const v = r.veil || {};
    chips([
      ['mode', v.mode, v.mode === 'full' ? 'good' : 'bad'],
      ['ocr', v.ocrOk ? 'ok' : 'FAILED', v.ocrOk ? 'good' : 'bad'],
      ['words scanned', v.wordsScanned ?? 0],
      ['text regions destroyed', v.textRegionsRedacted ?? 0, (v.textRegionsRedacted ? 'good' : '')],
      ['faces destroyed', v.facesRedacted ?? 0, (v.facesRedacted ? 'good' : '')],
      ['marks', r.marks.length],
      ['latency', (r.ms ?? 0) + ' ms'],
      ['pixel hash', String(r.pixelHash || '').slice(0, 12)],
    ]);
    await refreshVault();
  } catch (e) {
    logLine('capture', e.message, true);
    banner(e.blocked ? 'Capture blocked by the veil' : 'Capture failed', e.message);
  } finally {
    el.btnCapture.disabled = false;
  }
}

async function doRun() {
  const goal = el.goal.value.trim();
  if (!goal) { el.goal.focus(); return; }
  banner(null);
  try {
    await send('AAVARAN_RUN', { goal });
    setRunning(true);
  } catch (e) {
    logLine('run', e.message, true);
    banner('Could not start the run', e.message);
  }
}

async function doPreflight() {
  el.btnPreflight.disabled = true;
  banner(null);
  logLine('preflight', 'checking local assets and server…');
  try {
    const p = await send('AAVARAN_PREFLIGHT');
    dot(el.dSrv, p.server && p.server.reachable ? 'ok' : 'bad');
    if (p.assets && p.assets.problems && p.assets.problems.length) {
      for (const problem of p.assets.problems) logLine('asset', problem, true);
      banner('Local assets are broken — the veil cannot run',
        p.assets.problems[0]);
    } else {
      logLine('preflight', 'all local assets present and non-empty');
    }
    if (p.server && p.server.reachable) {
      logLine('preflight', `server ok · backend=${p.server.backend || '?'} model=${p.server.model || '?'}`);
    } else {
      logLine('preflight', `server unreachable: ${(p.server && p.server.error) || 'no response'}`, true);
    }
  } catch (e) {
    logLine('preflight', e.message, true);
  } finally {
    el.btnPreflight.disabled = false;
  }
}

async function doPurge() {
  try {
    const r = await send('AAVARAN_VAULT', { action: 'purge', filter: {} });
    logLine('vault', `purged ${r.removed} entries`);
    await refreshVault();
  } catch (e) {
    logLine('vault', e.message, true);
  }
}

/* --------------------------------------------------------------------------
 * Narrator — reads the page aloud with the browser's local speech engine.
 * Text comes from on-device OCR (reading order) plus DOM controls, so it
 * still works where markup is canvas or broken. Second press stops.
 * -------------------------------------------------------------------------- */
async function doNarrate() {
  if (speechSynthesis.speaking) { speechSynthesis.cancel(); return; }
  el.btnNarrate.disabled = true;
  try {
    const r = await send('AAVARAN_NARRATE');
    const controls = r.controls.filter((c) => c.name)
      .map((c, i) => `${i + 1}: ${c.role.replace('textbox:', '')}, ${c.name}${c.disabled ? ', disabled' : ''}`);
    const parts = [`Page: ${r.title || 'untitled'}.`, ...r.lines,
      `${controls.length} controls.`, ...controls];
    logLine('narrate', `${r.lines.length} lines, ${controls.length} controls`);
    for (const text of parts) {
      const u = new SpeechSynthesisUtterance(text);
      u.lang = 'en-IN';
      speechSynthesis.speak(u);
    }
  } catch (e) {
    logLine('narrate', e.message, true);
  } finally {
    el.btnNarrate.disabled = false;
  }
}

el.btnNarrate.addEventListener('click', doNarrate);
el.btnCapture.addEventListener('click', doCapture);
el.btnRun.addEventListener('click', doRun);
el.btnStop.addEventListener('click', () => send('AAVARAN_STOP').catch((e) => logLine('stop', e.message, true)));
el.btnPreflight.addEventListener('click', doPreflight);
el.btnVault.addEventListener('click', () => refreshVault().catch((e) => logLine('vault', e.message, true)));
el.btnPurge.addEventListener('click', doPurge);
el.goal.addEventListener('keydown', (e) => { if (e.key === 'Enter') doRun(); });

/* --------------------------------------------------------------------------
 * Boot. State first (cheap), then an automatic capture so the before/after is
 * populated the moment the panel opens — the demo should not require a click.
 * -------------------------------------------------------------------------- */
(async () => {
  try {
    const s = await refreshState();
    dot(el.dSrv, 'warn');
    await refreshVault();
    if (!(s.run && s.run.active)) await doCapture();
  } catch (e) {
    logLine('boot', e.message, true);
    banner('Service worker did not respond',
      'Open chrome://extensions → AAVARAN → "service worker" and check the console.');
  }
})();

// Keep the running state fresh while the popup is open.
setInterval(() => { refreshState().catch(() => {}); }, 2000);
