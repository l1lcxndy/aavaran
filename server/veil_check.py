"""
Server-side assertion that an observation's TEXT surfaces are veiled.

The client tokenizes the URL, title and mark names before egress and its own
egress guard scans the payload, so a hit here means a client-side bug. The
server refuses the frame rather than reasoning over leaked PII.

Pixel-level checks are deliberately absent: an entropy/edge heuristic on the
image cannot tell a redaction bar from a dark button, so it would only add
false confidence.
"""

from __future__ import annotations

import re

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


def verhoeff_valid(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    if len(digits) != 12 or digits[0] in "01":
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


# Same shapes as the client's EGRESS_PATTERNS / offscreen RULES.
_CHECKS = [
    ("AADHAAR", re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"), verhoeff_valid),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_valid),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), None),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"), None),
    ("PHONE", re.compile(r"(?:\+?91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b"), None),
]


def verify_veiled(texts: list[str]) -> list[str]:
    """Return the PII kinds found in raw form across `texts` (empty == clean)."""
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for kind, rx, valid in _CHECKS:
            if kind in found:
                continue
            if any(valid is None or valid(m.group(0)) for m in rx.finditer(text)):
                found.append(kind)
    return found


if __name__ == "__main__":
    assert verhoeff_valid("2345 6789 0124") and not verhoeff_valid("2345 6789 0125")
    assert luhn_valid("4111 1111 1111 1111") and not luhn_valid("4111 1111 1111 1112")
    assert verify_veiled(["Pay <PII:CARD#1> to <PII:EMAIL#2>", "https://bank.example/acct"]) == []
    assert set(verify_veiled(["mail rahul@example.com", "PAN ABCDE1234F"])) == {"PAN", "EMAIL"}
    assert verify_veiled(["call 98214 47063"]) == ["PHONE"]
    print("veil_check ok")
