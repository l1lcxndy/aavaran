'use strict';
/* Demo page behaviour. Kept in a separate file so the page works under a
   strict CSP and so nothing here can be mistaken for part of the extension. */

(function () {
  /* ---- face photo ------------------------------------------------------
   * Deliberately a local file picker rather than a bundled image: use a photo
   * of yourself or a teammate who has agreed to it. Two reasons — it dodges
   * every licensing question a judge might raise about a stock face, and
   * "that is my actual face, and it is gone" lands harder than a stock photo
   * ever will. The image never leaves this page; it is read with FileReader
   * straight into a data URL.
   * --------------------------------------------------------------------- */
  const drop = document.getElementById('drop');
  const file = document.getElementById('file');
  const avatar = document.getElementById('avatar');

  drop.addEventListener('click', () => file.click());
  file.addEventListener('change', () => {
    const f = file.files && file.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => {
      avatar.src = r.result;
      avatar.hidden = false;
      drop.hidden = true;
      try { localStorage.setItem('aavaran_demo_avatar', r.result); } catch { /* quota */ }
    };
    r.readAsDataURL(f);
  });

  // Persist across reloads so you are not re-picking the photo mid-demo.
  try {
    const saved = localStorage.getItem('aavaran_demo_avatar');
    if (saved) { avatar.src = saved; avatar.hidden = false; drop.hidden = true; }
  } catch { /* private mode */ }

  /* ---- actions ---------------------------------------------------------
   * Both buttons are inert. "Confirm and Pay" exists purely so the action
   * validator has a genuinely destructive control to refuse: its accessible
   * name matches DESTRUCTIVE_RE, so any agent proposal to click it returns
   * requiresConfirmation and stops for a human. Nothing is ever submitted.
   * --------------------------------------------------------------------- */
  const flash = (el, text, colour) => {
    const prev = el.textContent;
    el.textContent = text;
    el.style.background = colour;
    setTimeout(() => { el.textContent = prev; el.style.background = ''; }, 2200);
  };

  document.getElementById('pay').addEventListener('click', (e) => {
    e.preventDefault();
    flash(e.target, 'Blocked — demo fixture, nothing submitted', '#7f1d1d');
  });

  document.getElementById('dl').addEventListener('click', (e) => {
    e.preventDefault();
    flash(e.target, 'Statement ready (simulated)', '#047857');
  });
}());
