"""Score a veil run against bench ground truth.

    python bench/score.py bench/pages/labels.json predictions.json

labels.json      {page: [{kind, value, box?}]}            (from generate.py)
predictions.json {page: {"pred": [{kind?, value?, box?}], "latency_ms"?: float}}

A truth item counts as caught when a prediction has the same normalised value,
or a box with IoU >= 0.5. Recall is kind-agnostic: for redaction it only
matters that the span was destroyed, not what it was called.
Boxes are [x0, y0, x1, y1].
"""

import json
import re
import sys
from collections import defaultdict

IOU_HIT = 0.5


def calculate_iou(boxA, boxB):
    """Intersection over Union of two [x0, y0, x1, y1] boxes."""
    ix = max(0.0, min(boxA[2], boxB[2]) - max(boxA[0], boxB[0]))
    iy = max(0.0, min(boxA[3], boxB[3]) - max(boxA[1], boxB[1]))
    inter = ix * iy
    union = ((boxA[2] - boxA[0]) * (boxA[3] - boxA[1])
             + (boxB[2] - boxB[0]) * (boxB[3] - boxB[1]) - inter)
    return inter / union if union > 0 else 0.0


def _norm(v):
    return re.sub(r"[^0-9a-z@.]", "", str(v or "").lower())


def _hit(truth, pred):
    """IoU of the match (1.0 for a value match without boxes), or 0."""
    if truth.get("box") and pred.get("box"):
        iou = calculate_iou(truth["box"], pred["box"])
        if iou >= IOU_HIT:
            return iou
    tv, pv = _norm(truth.get("value")), _norm(pred.get("value"))
    return 1.0 if tv and pv and (tv == pv or tv in pv) else 0.0


def score_pipeline(results):
    """results: [{"truth": [...], "pred": [...], "latency_ms": float|None}]."""
    caught = defaultdict(int)
    total = defaultdict(int)
    true_pos_preds = n_preds = 0
    ious, lat = [], []
    for page in results:
        preds = page.get("pred") or []
        n_preds += len(preds)
        used = set()
        for t in page.get("truth") or []:
            total[t["kind"]] += 1
            best, best_j = 0.0, None
            for j, p in enumerate(preds):
                h = _hit(t, p)
                if h > best:
                    best, best_j = h, j
            if best_j is not None:
                caught[t["kind"]] += 1
                used.add(best_j)
                if t.get("box") and preds[best_j].get("box"):
                    ious.append(best)
        true_pos_preds += len(used)
        if page.get("latency_ms") is not None:
            lat.append(float(page["latency_ms"]))

    n_truth = sum(total.values())
    lat.sort()
    return {
        "recall": sum(caught.values()) / n_truth if n_truth else None,
        "precision": true_pos_preds / n_preds if n_preds else None,
        "mean_iou": sum(ious) / len(ious) if ious else None,
        "p95_latency_ms": lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else None,
        "recall_by_kind": {k: round(caught[k] / total[k], 3) for k in sorted(total)},
        "pages": len(results),
    }


def _selftest():
    assert calculate_iou([0, 0, 10, 10], [0, 0, 10, 10]) == 1.0
    assert calculate_iou([0, 0, 10, 10], [20, 20, 30, 30]) == 0.0
    assert abs(calculate_iou([0, 0, 10, 10], [5, 0, 15, 10]) - 1 / 3) < 1e-9
    r = score_pipeline([
        {"truth": [{"kind": "PAN", "value": "ABCPD1234F"}, {"kind": "NAME", "value": "R Sharma"}],
         "pred": [{"kind": "PAN", "value": "abcpd1234f"}, {"kind": "X", "value": "noise"}],
         "latency_ms": 100},
        {"truth": [{"kind": "FACE", "box": [0, 0, 10, 10]}],
         "pred": [{"box": [1, 1, 10, 10]}], "latency_ms": 300},
    ])
    assert r["recall"] == 2 / 3 and r["precision"] == 2 / 3, r
    assert r["recall_by_kind"] == {"FACE": 1.0, "NAME": 0.0, "PAN": 1.0}
    assert abs(r["mean_iou"] - 0.81) < 1e-9 and r["p95_latency_ms"] == 300
    print("score selftest ok")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        _selftest()
        sys.exit(0)
    with open(sys.argv[1], encoding="utf-8") as f:
        labels = json.load(f)
    with open(sys.argv[2], encoding="utf-8") as f:
        preds = json.load(f)
    rows = [{"truth": truth, **(preds.get(page) or {"pred": []})} for page, truth in labels.items()]
    print(json.dumps(score_pipeline(rows), indent=2))
