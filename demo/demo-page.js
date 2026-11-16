'use strict';
/* Demo page behaviour. Kept in a separate file so the page works under a
   strict CSP and so nothing here can be mistaken for part of the extension. */

(function () {
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

  // Persistent success state: a flash that reverts gives an agent no evidence
  // the goal was met, so it keeps clicking.
  document.getElementById('dl').addEventListener('click', (e) => {
    e.preventDefault();
    e.target.textContent = 'Statement downloaded ✓ (simulated)';
    e.target.style.background = '#047857';
    e.target.disabled = true;
  });
}());
