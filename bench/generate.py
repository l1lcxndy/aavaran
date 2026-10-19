"""Synthetic PII benchmark: N HTML pages with valid-checksum Indian identifiers.

Writes pages/page_NNN.html plus labels.json ({page: [{kind, value}]}), the
ground truth score.py measures recall against. Every value is fabricated.

    python bench/generate.py --n 200
"""

import argparse
import json
import random
import string
from pathlib import Path

HERE = Path(__file__).resolve().parent

_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

FIRST = ["Rahul", "Priya", "Arjun", "Ananya", "Vikram", "Meera", "Rohan", "Kavya"]
LAST = ["Sharma", "Iyer", "Reddy", "Gupta", "Nair", "Patel", "Singh", "Das"]
PSP = ["okaxis", "ybl", "okhdfcbank", "paytm", "oksbi"]
BANKS = ["SBIN", "HDFC", "ICIC", "UTIB", "PUNB"]


def verhoeff_check_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def aadhaar(rng: random.Random) -> str:
    body = str(rng.randint(2, 9)) + "".join(rng.choices(string.digits, k=10))
    n = body + verhoeff_check_digit(body)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def pan(rng: random.Random) -> str:
    up = string.ascii_uppercase
    return "".join(rng.choices(up, k=3)) + "P" + rng.choice(up) + "".join(rng.choices(string.digits, k=4)) + rng.choice(up)


def ifsc(rng: random.Random) -> str:
    return rng.choice(BANKS) + "0" + "".join(rng.choices(string.digits, k=6))


def phone(rng: random.Random) -> str:
    n = str(rng.randint(6, 9)) + "".join(rng.choices(string.digits, k=9))
    return rng.choice([n, f"{n[:5]} {n[5:]}", f"+91 {n}"])


def name(rng: random.Random) -> str:
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def generate_pii_page(filename: Path, rng: random.Random) -> list[dict[str, str]]:
    """Write one page; return its ground-truth PII list."""
    who = name(rng)
    handle = who.split()[0].lower() + str(rng.randint(1, 99))
    fields = [
        ("NAME", "Name", who),
        ("AADHAAR", "Aadhaar", aadhaar(rng)),
        ("PAN", "PAN", pan(rng)),
        ("PHONE", "Mobile", phone(rng)),
        ("EMAIL", "Email", f"{handle}@example.in"),
        ("UPI", "UPI ID", f"{handle}@{rng.choice(PSP)}"),
        ("IFSC", "IFSC", ifsc(rng)),
    ]
    rng.shuffle(fields)
    shown = fields[: rng.randint(4, len(fields))]
    rows = "\n".join(
        f'      <tr><td>{label}</td><td><span data-pii="{kind}">{value}</span></td></tr>'
        for kind, label, value in shown
    )
    filename.write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Account profile</title>
<style>body{{font:16px sans-serif;margin:40px}} td{{padding:6px 14px}}</style></head>
<body>
  <h1>Account profile</h1>
  <table>
{rows}
  </table>
  <button id="submit">Submit</button>
</body></html>
""", encoding="utf-8")
    return [{"kind": kind, "value": value} for kind, _, value in shown]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=26171)
    ap.add_argument("--out", type=Path, default=HERE / "pages")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    args.out.mkdir(parents=True, exist_ok=True)
    labels = {}
    for i in range(args.n):
        page = args.out / f"page_{i:03d}.html"
        labels[page.name] = generate_pii_page(page, rng)
    (args.out / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")
    print(f"wrote {args.n} pages + labels.json to {args.out}")


if __name__ == "__main__":
    main()
