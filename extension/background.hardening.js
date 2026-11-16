'use strict';

(function (root) {

  // Never execute purely on the server's say-so. The server is the thing
  // talking to an untrusted model; the extension is the thing with the
  // user's cookies. Validation runs on both sides with the same table.
  const ALLOWED_ACTIONS = Object.freeze({
    click: { index: 'int' },
    double_click: { index: 'int' },
    type: { index: 'int', text: 'string', submit: 'bool?' },
    clear: { index: 'int' },
    press_key: { key: 'string', index: 'int?' },
    select_option: { index: 'int', value: 'string' },
    scroll: { direction: 'string', amount: 'int?', index: 'int?' },
    hover: { index: 'int' },
    navigate: { url: 'string' },
    go_back: {},
    wait: { ms: 'int?' },
    extract: { index: 'int?', what: 'string?' },
    ask_user: { question: 'string' },
    finish: { summary: 'string', success: 'bool?' },
  });

  const ALLOWED_KEYS = new Set([
    'Enter', 'Tab', 'Escape', 'Backspace', 'Delete',
    'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
    'PageUp', 'PageDown', 'Home', 'End',
  ]);

  const SELECTABLE_ROLES = new Set(['select', 'combobox', 'listbox']);
  const PII_TOKEN_RE = /<PII:[A-Z_]+#\d+>/g;
  const DESTRUCTIVE_RE = /\b(pay|transfer|send\s*money|delete|remove|deactivate|close\s*account|withdraw|place\s*order|buy\s*now|confirm\s*(and\s*)?(pay|order|transfer)|authori[sz]e)\b/i;

  class ActionRejected extends Error {
    constructor(code, detail) { super(`${code}: ${detail}`); this.code = code; this.detail = detail; }
  }

  function validateAction(action, marks, ctx) {
    if (!action || typeof action !== 'object') throw new ActionRejected('malformed', 'not an object');
    const type = String(action.type || action.action || '');
    const spec = ALLOWED_ACTIONS[type];
    if (!spec) {
      throw new ActionRejected('unknown_action',
        `"${type}" is not executable. Allowed: ${Object.keys(ALLOWED_ACTIONS).join(', ')}`);
    }

    // Reject unknown fields: a model inventing `selector` has left the index-grounding contract.
    const allowedKeys = new Set([...Object.keys(spec), 'type', 'action', 'reason', 'confidence']);
    for (const k of Object.keys(action)) {
      if (!allowedKeys.has(k)) throw new ActionRejected('unknown_field', `"${k}" is not a field of ${type}`);
    }
    for (const [field, kind] of Object.entries(spec)) {
      const optional = kind.endsWith('?');
      const v = action[field];
      if (v === undefined || v === null) {
        if (!optional) throw new ActionRejected('missing_field', `${type} requires "${field}"`);
        continue;
      }
      const base = optional ? kind.slice(0, -1) : kind;
      if (base === 'int' && !Number.isInteger(v)) throw new ActionRejected('bad_type', `"${field}" must be an integer`);
      if (base === 'string' && typeof v !== 'string') throw new ActionRejected('bad_type', `"${field}" must be a string`);
      if (base === 'bool' && typeof v !== 'boolean') throw new ActionRejected('bad_type', `"${field}" must be a boolean`);
    }

    const byId = new Map(marks.map((m) => [m.id, m]));
    let mark = null;
    if (action.index !== undefined && action.index !== null) {
      mark = byId.get(action.index);
      if (!mark) {
        throw new ActionRejected('bad_index',
          `[${action.index}] is not on this frame. Valid: ${marks.slice(0, 40).map((m) => m.id).join(', ')}`);
      }
    }

    if (type === 'type' || type === 'clear') {
      if (!mark.editable) {
        throw new ActionRejected('not_editable', `[${action.index}] is a ${mark.role}, not a text input`);
      }
    }
    if (type === 'select_option') {
      if (!SELECTABLE_ROLES.has(String(mark.role || '').toLowerCase())) {
        throw new ActionRejected('not_selectable', `[${action.index}] is a ${mark.role}, not a select`);
      }
      const opts = mark.options || [];
      if (opts.length && !opts.includes(action.value)) {
        throw new ActionRejected('bad_option', `"${action.value}" not in [${opts.join(', ')}]`);
      }
    }
    if (type === 'press_key' && !ALLOWED_KEYS.has(action.key)) {
      throw new ActionRejected('bad_key', `"${action.key}" not in [${[...ALLOWED_KEYS].join(', ')}]`);
    }
    if (type === 'scroll') {
      if (!['up', 'down', 'left', 'right', 'top', 'bottom'].includes(action.direction)) {
        throw new ActionRejected('bad_direction', `"${action.direction}" is not a scroll direction`);
      }
      if (action.amount !== undefined && (action.amount < 0 || action.amount > 5000)) {
        throw new ActionRejected('bad_amount', 'scroll amount must be 0..5000');
      }
    }
    if (type === 'wait') {
      if (action.ms !== undefined && (action.ms < 0 || action.ms > 15000)) {
        throw new ActionRejected('bad_wait', 'wait must be 0..15000ms');
      }
    }
    if (type === 'navigate') {
      let u;
      try { u = new URL(action.url); } catch { throw new ActionRejected('bad_url', `"${action.url}" is not a URL`); }
      if (!/^https?:$/.test(u.protocol)) {
        throw new ActionRejected('bad_scheme', `${u.protocol} is not allowed; only http and https`);
      }
      const allow = ctx.navAllowlist || [];
      if (allow.length && !allow.some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`))) {
        throw new ActionRejected('host_not_allowed', `${u.hostname} is outside the run's allowlist`);
      }
    }

    // Tokens are bound to their capture origin; typing one on another origin is a hard stop.
    if (type === 'type' && typeof action.text === 'string') {
      const tokens = action.text.match(PII_TOKEN_RE) || [];
      let origin = '';
      try { origin = new URL(ctx.url).origin; } catch { /* ignore */ }
      for (const t of tokens) {
        const rec = (ctx.vault || {})[t];
        if (!rec) throw new ActionRejected('unknown_token', `${t} is not in the vault`);
        if (rec.origin && rec.origin !== origin) {
          throw new ActionRejected('cross_origin_pii',
            `${t} was captured on ${rec.origin} and cannot be typed on ${origin}`);
        }
      }
      if (action.text.length > 2000) throw new ActionRejected('text_too_long', 'max 2000 chars');
    }

    // Loop breaker. Three identical actions with no pixel change means the
    // model is stuck; feeding that back as a rejection is far more useful
    // than letting it burn the step budget.
    const sig = JSON.stringify({ type, index: action.index ?? null, text: action.text ?? null });
    const hist = ctx.history || [];
    const repeats = hist.slice(-3).filter((h) => h.sig === sig && h.noop).length;
    if (repeats >= 2) {
      throw new ActionRejected('repeated_noop',
        `this exact action has already been tried ${repeats + 1}x with no change to the page; try a different element or scroll`);
    }

    const needsConfirm = DESTRUCTIVE_RE.test(`${mark ? mark.name : ''} ${action.text || ''} ${action.reason || ''}`)
      || (type === 'click' && mark && DESTRUCTIVE_RE.test(mark.name || ''));

    return { action: { ...action, type }, mark, sig, requiresConfirmation: needsConfirm };
  }

  root.AAVARAN_BG = { ALLOWED_ACTIONS, ALLOWED_KEYS, validateAction, ActionRejected };
}(self));
