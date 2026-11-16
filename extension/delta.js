'use strict';

(function (root) {
  const TILE = 64;                 // egress px per tile edge
  const SAMPLE_STRIDE = 2;         // sample every 2nd px in both axes
  const FNV_OFFSET = 0x811c9dc5;
  const FNV_PRIME = 0x01000193;

  function tileGrid(canvas, tile = TILE) {
    const W = canvas.width;
    const H = canvas.height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const { data } = ctx.getImageData(0, 0, W, H);
    const cols = Math.ceil(W / tile);
    const rows = Math.ceil(H / tile);
    const hashes = new Uint32Array(cols * rows);

    for (let ty = 0; ty < rows; ty++) {
      const y0 = ty * tile;
      const y1 = Math.min(H, y0 + tile);
      for (let tx = 0; tx < cols; tx++) {
        const x0 = tx * tile;
        const x1 = Math.min(W, x0 + tile);
        let h = FNV_OFFSET;
        for (let y = y0; y < y1; y += SAMPLE_STRIDE) {
          let o = (y * W + x0) * 4;
          for (let x = x0; x < x1; x += SAMPLE_STRIDE, o += 4 * SAMPLE_STRIDE) {
            // Quantise to 5 bits/channel: kills sub-pixel AA jitter and
            // scrollbar shimmer, keeps real content changes.
            h ^= ((data[o] >> 3) | ((data[o + 1] >> 3) << 5) | ((data[o + 2] >> 3) << 10)) & 0x7fff;
            h = Math.imul(h, FNV_PRIME);
          }
        }
        hashes[ty * cols + tx] = h >>> 0;
      }
    }
    return { cols, rows, tile, width: W, height: H, hashes };
  }

  function diffGrid(prev, next) {
    if (!prev
      || prev.cols !== next.cols || prev.rows !== next.rows
      || prev.width !== next.width || prev.height !== next.height) {
      return {
        full: true,
        ratio: 1,
        rects: [[0, 0, next.width, next.height]],
        union: [0, 0, next.width, next.height],
        dirtyTiles: next.cols * next.rows,
        totalTiles: next.cols * next.rows,
      };
    }

    const { cols, rows, tile, width, height } = next;
    const dirty = new Uint8Array(cols * rows);
    let count = 0;
    for (let i = 0; i < dirty.length; i++) {
      if (prev.hashes[i] !== next.hashes[i]) { dirty[i] = 1; count++; }
    }
    if (!count) {
      return { full: false, ratio: 0, rects: [], union: null, dirtyTiles: 0, totalTiles: dirty.length };
    }

    // Dilate by one tile. A caret, a focus ring or a hover state routinely
    // straddles a tile boundary; a tight patch leaves a one-pixel seam that
    // reads to the VLM as a rendering artifact.
    const grown = new Uint8Array(dirty.length);
    for (let ty = 0; ty < rows; ty++) {
      for (let tx = 0; tx < cols; tx++) {
        if (!dirty[ty * cols + tx]) continue;
        for (let dy = -1; dy <= 1; dy++) {
          for (let dx = -1; dx <= 1; dx++) {
            const y = ty + dy; const x = tx + dx;
            if (y < 0 || x < 0 || y >= rows || x >= cols) continue;
            grown[y * cols + x] = 1;
          }
        }
      }
    }

    // Run-length merge per row, then vertically coalesce runs with identical
    // x-extent. Produces a handful of rects instead of hundreds of tiles.
    /** @type {number[][]} */
    const runs = [];
    for (let ty = 0; ty < rows; ty++) {
      let start = -1;
      for (let tx = 0; tx <= cols; tx++) {
        const on = tx < cols && grown[ty * cols + tx];
        if (on && start < 0) start = tx;
        if (!on && start >= 0) { runs.push([start, ty, tx, ty + 1]); start = -1; }
      }
    }
    const merged = [];
    const used = new Array(runs.length).fill(false);
    for (let i = 0; i < runs.length; i++) {
      if (used[i]) continue;
      const cur = runs[i].slice();
      used[i] = true;
      for (let j = i + 1; j < runs.length; j++) {
        if (used[j]) continue;
        const r = runs[j];
        if (r[0] === cur[0] && r[2] === cur[2] && r[1] === cur[3]) {
          cur[3] = r[3];
          used[j] = true;
        }
      }
      merged.push(cur);
    }

    const rects = merged.map(([tx0, ty0, tx1, ty1]) => [
      tx0 * tile,
      ty0 * tile,
      Math.min(width, tx1 * tile),
      Math.min(height, ty1 * tile),
    ]);

    let ux0 = Infinity; let uy0 = Infinity; let ux1 = -Infinity; let uy1 = -Infinity;
    for (const r of rects) {
      ux0 = Math.min(ux0, r[0]); uy0 = Math.min(uy0, r[1]);
      ux1 = Math.max(ux1, r[2]); uy1 = Math.max(uy1, r[3]);
    }

    return {
      full: false,
      ratio: count / dirty.length,
      rects,
      union: [ux0, uy0, ux1, uy1],
      dirtyTiles: count,
      totalTiles: dirty.length,
    };
  }

  const POLICY_DEFAULTS = Object.freeze({
    // Above this fraction of changed tiles a patch stops paying for itself —
    // the PNG of the union box approaches the size of the whole frame.
    maxPatchRatio: 0.30,
    // Union box may not exceed this fraction of frame area.
    maxPatchArea: 0.45,
    // Force a full keyframe at least this often, so a long run of patches
    // cannot accumulate drift in the server's reconstruction.
    keyframeEvery: 8,
    // Below this, treat as no visual change at all.
    stillRatio: 0.0,
  });

  function choose(diff, grid, opts) {
    const cfg = { ...POLICY_DEFAULTS, ...(opts || {}) };
    if (cfg.forceFull || diff.full) {
      return { mode: 'full', reason: cfg.forceFull ? 'keyframe_forced' : 'geometry_changed' };
    }
    if (diff.ratio <= cfg.stillRatio) return { mode: 'unchanged', reason: 'no_dirty_tiles' };
    if ((cfg.stepsSinceKeyframe || 0) >= cfg.keyframeEvery) {
      return { mode: 'full', reason: 'keyframe_interval' };
    }
    if (diff.ratio > cfg.maxPatchRatio) return { mode: 'full', reason: 'change_ratio' };

    const [x0, y0, x1, y1] = diff.union;
    const areaFrac = ((x1 - x0) * (y1 - y0)) / (grid.width * grid.height);
    if (!Number.isFinite(areaFrac) || areaFrac > cfg.maxPatchArea) {
      return { mode: 'full', reason: 'union_too_large' };
    }
    return { mode: 'patch', reason: 'localised', rect: [x0, y0, x1 - x0, y1 - y0], areaFrac };
  }

  // Content-addressed mark ids so [14] names the same element across re-layouts.
  class StableMarkIds {
    constructor() { this.byKey = new Map(); this.next = 1; }

    key(m) {
      const b = m.bbox || [0, 0, 0, 0];
      return [
        (m.role || '').toLowerCase(),
        (m.name || '').trim().slice(0, 64).toLowerCase(),
        m.editable ? 'e' : '-',
        Math.round(b[0] / 16), Math.round(b[1] / 16),
        Math.round((b[2] - b[0]) / 16), Math.round((b[3] - b[1]) / 16),
      ].join('|');
    }

    assign(marks) {
      const seen = new Set();
      for (const m of marks) {
        const k = this.key(m);
        let id = this.byKey.get(k);
        if (!id || seen.has(id)) { id = this.next++; this.byKey.set(k, id); }
        seen.add(id);
        m.id = id;
      }
      // Forget elements gone for good so the map stays bounded on long runs.
      if (this.byKey.size > 600) {
        const live = new Set(marks.map((m) => this.key(m)));
        for (const k of [...this.byKey.keys()]) if (!live.has(k)) this.byKey.delete(k);
      }
      return marks;
    }
  }

  root.AAVARAN_DELTA = { TILE, tileGrid, diffGrid, choose, POLICY_DEFAULTS, StableMarkIds };
}(self));
