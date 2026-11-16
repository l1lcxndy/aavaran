'use strict';
(async () => {
  const W = 1280;
  const H = 720;
  const out = document.getElementById('out');
  const q = new URLSearchParams(location.search);
  const n = Number(q.get('n') || 20);
  const start = Number(q.get('start') || 0);
  const show = Number(q.get('show') || 2);
  // ?dpr=2 renders a high-DPI capture of the same CSS layout (truth in device px).
  const dpr = Number(q.get('dpr') || 1);
  // Name rows alternate between labelled and bare prose, so the bare ones can
  // only be caught by the NER model.
  const NAME_LABELS = ['Name', 'Account holder', 'Prepared for'];

  function render(items, i) {
    const c = document.createElement('canvas');
    c.width = W * dpr; c.height = H * dpr;
    const x = c.getContext('2d');
    x.scale(dpr, dpr);
    x.fillStyle = '#fff'; x.fillRect(0, 0, W, H);
    x.fillStyle = '#111'; x.font = 'bold 30px Arial'; x.fillText('Account profile', 60, 60);
    x.font = '22px Arial';
    const truth = [];
    items.forEach((it, row) => {
      const y = 120 + row * 52;
      const label = it.kind === 'NAME' ? NAME_LABELS[i % 3] : it.kind;
      x.fillText(label, 60, y);
      x.fillText(it.value, 330, y);
      const m = x.measureText(it.value);
      truth.push({ ...it, box: [330, y - m.actualBoundingBoxAscent, 330 + m.width, y + m.actualBoundingBoxDescent].map((v) => v * dpr) });
    });
    x.fillStyle = '#1f6feb'; x.fillRect(60, H - 90, 140, 44);
    x.fillStyle = '#fff'; x.fillText('Submit', 95, H - 60);
    return { dataUrl: c.toDataURL('image/png'), truth };
  }

  const labels = await (await fetch('pages/labels.json')).json();
  const pages = Object.keys(labels).slice(start, start + n);
  const result = { labels: {}, predictions: {}, warnings: new Set() };
  for (const [i, page] of pages.entries()) {
    const { dataUrl, truth } = render(labels[page], start + i);
    const t0 = performance.now();
    const r = await veil({
      rawDataUrl: dataUrl, domMarks: [], opaque: [], knownTokens: {},
      viewport: { cssWidth: W, cssHeight: H, url: 'https://bench.local/profile', title: 'Account profile' },
      config: q.has('pad') ? { redactionPad: Number(q.get('pad')) } : {},
    });
    const ms = performance.now() - t0;
    result.labels[page] = truth;
    result.predictions[page] = {
      pred: (r.veil ? r.veil.boxes : []).map((box) => ({ box })),
      latency_ms: ms,
      timings: r.veil && r.veil.timings,
      faces: r.veil && r.veil.facesRedacted,
    };
    (r.warnings || []).forEach((w) => result.warnings.add(w));
    if (i < show) {
      for (const src of [dataUrl, r.veiledDataUrl]) {
        const img = new Image(); img.src = src; document.getElementById('frames').appendChild(img);
      }
    }
    out.textContent = `page ${i + 1}/${pages.length} · ${Math.round(ms)}ms · mode=${r.veil && r.veil.mode}`
      + ` · ner=${NER.device || (NER.failed ? 'failed' : '?')}`;
  }
  result.warnings = [...result.warnings];
  window.AAVARAN_BENCH = result;
  for (const key of ['labels', 'predictions']) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(result[key])], { type: 'application/json' }));
    a.download = `veil_${key}.json`;
    a.textContent = ` download ${a.download}`;
    out.after(a);
  }
  out.textContent += '\nDONE';
})().catch((e) => {
  document.getElementById('out').textContent = 'FAILED: ' + (e && e.stack || e);
});
