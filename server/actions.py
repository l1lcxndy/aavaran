"""
AAVARAN — actions.py
====================
The executable action surface, and the gate every VLM proposal passes through.

Design stance: the whitelist is *closed*. A model that emits `execute_script`,
`xpath`, or `click_at(x, y)` is not producing a slightly-wrong action, it has
left the grounding contract — the whole point of Set-of-Mark is that the model
answers with an index that either exists in the manifest or does not. Rejecting
unknown fields (rather than ignoring them) keeps that property, because an
ignored field means we execute something different from what the model reasoned
about.

Rejections are returned to the model as a repair prompt rather than aborting the
run. In practice a 7B-class VLM fixes 80-90% of schema violations on the first
retry, and the rejection text is what teaches it the index space.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse

from veil_check import verify_veiled


class ActionRejected(Exception):
    def __init__(self, code: str, detail: str, hint: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.hint = hint

    def repair_prompt(self) -> str:
        base = f"REJECTED ({self.code}): {self.detail}"
        return f"{base}\n{self.hint}" if self.hint else base


# name -> {field: (python_type, required)}
ACTION_SPECS: dict[str, dict[str, tuple[type | tuple[type, ...], bool]]] = {
    "click":         {"index": (int, True)},
    "double_click":  {"index": (int, True)},
    "type":          {"index": (int, True), "text": (str, True), "submit": (bool, False)},
    "clear":         {"index": (int, True)},
    "press_key":     {"key": (str, True), "index": (int, False)},
    "select_option": {"index": (int, True), "value": (str, True)},
    "scroll":        {"direction": (str, True), "amount": (int, False), "index": (int, False)},
    "hover":         {"index": (int, True)},
    "navigate":      {"url": (str, True)},
    "go_back":       {},
    "wait":          {"ms": (int, False)},
    "extract":       {"index": (int, False), "what": (str, False)},
    "ask_user":      {"question": (str, True)},
    "finish":        {"summary": (str, True), "success": (bool, False)},
}

COMMON_FIELDS = {"type", "action", "reason", "confidence"}

ALLOWED_KEYS = {
    "Enter", "Tab", "Escape", "Backspace", "Delete",
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "PageUp", "PageDown", "Home", "End",
}

SCROLL_DIRECTIONS = {"up", "down", "left", "right", "top", "bottom"}
SELECTABLE_ROLES = {"select", "combobox", "listbox"}

# Kinds include underscores (AADHAAR_SUSPECT, GROUPED_ID); without them such a
# token would skip the vault/origin check entirely.
PII_TOKEN_RE = re.compile(r"<PII:[A-Z_]+#\d+>")
RAW_ID_RE = re.compile(r"(?:\d[\s-]?){8,}\d")   # 9+ digits: Aadhaar, card, account, phone

DESTRUCTIVE_RE = re.compile(
    r"\b(pay|payment|transfer|send\s*money|remit|delete|remove|deactivate|"
    r"close\s*account|withdraw|place\s*order|buy\s*now|checkout|"
    r"confirm\s*(and\s*)?(pay|order|transfer)?|authori[sz]e|submit\s*claim)\b",
    re.IGNORECASE,
)

MAX_TEXT_LEN = 2000
MAX_SCROLL = 5000
MAX_WAIT_MS = 15_000


@dataclass
class ValidationContext:
    url: str
    marks: list[dict[str, Any]]
    vault: dict[str, dict[str, Any]] = field(default_factory=dict)
    nav_allowlist: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    step: int = 0
    max_steps: int = 40


@dataclass
class ValidatedAction:
    action: dict[str, Any]
    mark: dict[str, Any] | None
    signature: str
    requires_confirmation: bool
    risk: str = "low"


def schema_text() -> str:
    """Rendered into the system prompt. Kept in one place so the prompt and the
    validator cannot drift apart — prompt/validator drift is the single largest
    source of avoidable repair loops."""
    lines = ["You may emit exactly one of these actions, as a single JSON object:"]
    for name, spec in ACTION_SPECS.items():
        if not spec:
            lines.append(f'  {{"type": "{name}"}}')
            continue
        parts = []
        for f, (t, req) in spec.items():
            tn = {int: "int", str: "string", bool: "bool"}.get(t, "any")
            parts.append(f'"{f}": <{tn}>' + ("" if req else "   // optional"))
        lines.append(f'  {{"type": "{name}", ' + ", ".join(parts) + "}")
    lines.append("")
    lines.append(f"press_key.key must be one of: {', '.join(sorted(ALLOWED_KEYS))}")
    lines.append(f"scroll.direction must be one of: {', '.join(sorted(SCROLL_DIRECTIONS))}")
    lines.append('"index" must be a number that appears as a labelled box in the screenshot.')
    lines.append("Never invent an index. Never emit CSS selectors, XPath, JavaScript, or pixel coordinates.")
    lines.append('Also include "reason": a one-sentence justification, and "confidence": 0.0-1.0.')
    return "\n".join(lines)


def json_schema(mark_ids: Iterable[int] = ()) -> dict[str, Any]:
    """JSON Schema of the action space, for grammar-constrained decoding
    (vLLM + XGrammar via response_format=json_schema). Generated from
    ACTION_SPECS so decoder, prompt and validator cannot drift. With mark ids,
    "index" is an enum of the boxes actually on screen: the model cannot even
    emit an index that does not exist."""
    ids = sorted(set(mark_ids))
    py_to_json = {int: "integer", str: "string", bool: "boolean"}
    variants = []
    for name, spec in ACTION_SPECS.items():
        props: dict[str, Any] = {
            "type": {"const": name},
            "reason": {"type": "string"},
            "confidence": {"type": "number"},
        }
        required = ["type"]
        for fname, (ftype, req) in spec.items():
            prop: dict[str, Any] = {"type": py_to_json[ftype]}
            if fname == "index" and ids:
                prop = {"enum": ids}
            elif fname == "key":
                prop["enum"] = sorted(ALLOWED_KEYS)
            elif fname == "direction":
                prop["enum"] = sorted(SCROLL_DIRECTIONS)
            props[fname] = prop
            if req:
                required.append(fname)
        variants.append({"type": "object", "properties": props,
                         "required": required, "additionalProperties": False})
    return {"anyOf": variants}


def _coerce(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        # Models wrap JSON in fences or prose even when told not to.
        fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
        if fence:
            text = fence.group(1).strip()
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            text = text[start : end + 1]
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ActionRejected(
                "malformed_json",
                f"could not parse your output as JSON ({e.msg})",
                "Reply with a single JSON object and nothing else.",
            )
    raise ActionRejected("malformed", f"expected an object, got {type(raw).__name__}")


def validate(raw: Any, ctx: ValidationContext) -> ValidatedAction:
    obj = _coerce(raw)

    if ctx.step >= ctx.max_steps:
        raise ActionRejected(
            "step_budget",
            f"step budget of {ctx.max_steps} exhausted",
            'Emit {"type": "finish", ...} summarising what was accomplished.',
        )

    atype = str(obj.get("type") or obj.get("action") or "").strip()
    spec = ACTION_SPECS.get(atype)
    if spec is None:
        raise ActionRejected(
            "unknown_action",
            f'"{atype}" is not an executable action',
            f"Allowed: {', '.join(ACTION_SPECS)}.",
        )

    allowed = set(spec) | COMMON_FIELDS
    extra = set(obj) - allowed
    if extra:
        raise ActionRejected(
            "unknown_field",
            f"{atype} has no field(s) {sorted(extra)}",
            f"{atype} accepts only: {sorted(set(spec)) or 'no fields'}.",
        )

    for fname, (ftype, required) in spec.items():
        if fname not in obj or obj[fname] is None:
            if required:
                raise ActionRejected("missing_field", f'{atype} requires "{fname}"')
            continue
        val = obj[fname]
        # bool is a subclass of int in Python; do not let True satisfy an int field.
        if ftype is int and (isinstance(val, bool) or not isinstance(val, int)):
            raise ActionRejected("bad_type", f'"{fname}" must be an integer, got {val!r}')
        if ftype is str and not isinstance(val, str):
            raise ActionRejected("bad_type", f'"{fname}" must be a string, got {val!r}')
        if ftype is bool and not isinstance(val, bool):
            raise ActionRejected("bad_type", f'"{fname}" must be true or false, got {val!r}')

    by_id = {m["id"]: m for m in ctx.marks}
    mark: dict[str, Any] | None = None
    if obj.get("index") is not None:
        mark = by_id.get(obj["index"])
        if mark is None:
            visible = ", ".join(str(m["id"]) for m in ctx.marks[:50])
            raise ActionRejected(
                "bad_index",
                f'[{obj["index"]}] does not exist on this frame',
                f"Indices on screen right now: {visible}",
            )

    if atype in {"type", "clear"} and not mark.get("editable"):
        raise ActionRejected(
            "not_editable",
            f'[{obj["index"]}] is a {mark.get("role")} ("{mark.get("name","")}"), not a text field',
            "Pick a box drawn in yellow — those are the editable ones.",
        )

    if atype == "select_option":
        role = str(mark.get("role", "")).lower()
        if role not in SELECTABLE_ROLES:
            raise ActionRejected("not_selectable", f'[{obj["index"]}] is a {role}, not a select')
        options = mark.get("options") or []
        if options and obj["value"] not in options:
            raise ActionRejected(
                "bad_option",
                f'"{obj["value"]}" is not an option of [{obj["index"]}]',
                f"Options: {options}",
            )

    if atype == "press_key" and obj["key"] not in ALLOWED_KEYS:
        raise ActionRejected(
            "bad_key", f'"{obj["key"]}" is not a permitted key',
            f"Permitted: {', '.join(sorted(ALLOWED_KEYS))}",
        )

    if atype == "scroll":
        if obj["direction"] not in SCROLL_DIRECTIONS:
            raise ActionRejected("bad_direction", f'"{obj["direction"]}" is not a direction')
        amt = obj.get("amount")
        if amt is not None and not (0 <= amt <= MAX_SCROLL):
            raise ActionRejected("bad_amount", f"scroll amount must be 0..{MAX_SCROLL}")

    if atype == "wait":
        ms = obj.get("ms")
        if ms is not None and not (0 <= ms <= MAX_WAIT_MS):
            raise ActionRejected("bad_wait", f"wait must be 0..{MAX_WAIT_MS}ms")

    if atype == "navigate":
        parsed = urlparse(obj["url"])
        if parsed.scheme not in {"http", "https"}:
            raise ActionRejected(
                "bad_scheme", f"{parsed.scheme or 'missing'} is not permitted",
                "Only http and https. javascript:, data: and file: are blocked.",
            )
        host = (parsed.hostname or "").lower()
        if ctx.nav_allowlist and not any(
            host == h or host.endswith("." + h) for h in ctx.nav_allowlist
        ):
            raise ActionRejected(
                "host_not_allowed",
                f"{host} is outside this run's allowlist",
                f"Allowed hosts: {', '.join(ctx.nav_allowlist)}",
            )

    if atype == "type":
        text = obj["text"]
        if len(text) > MAX_TEXT_LEN:
            raise ActionRejected("text_too_long", f"max {MAX_TEXT_LEN} characters")
        current_origin = _origin(ctx.url)
        for token in PII_TOKEN_RE.findall(text):
            rec = ctx.vault.get(token)
            if rec is None:
                raise ActionRejected(
                    "unknown_token", f"{token} is not in the vault",
                    "Only reference PII tokens that appear on the current frame.",
                )
            captured = rec.get("origin")
            if captured and captured != current_origin:
                # Hard stop. Not a confirmation prompt — a model moving a card
                # number from the issuer's origin to another origin is
                # describing exfiltration regardless of intent.
                raise ActionRejected(
                    "cross_origin_pii",
                    f"{token} was captured on {captured} and cannot be entered on {current_origin}",
                    "Do not move redacted values between sites.",
                )
        # The model never sees a PII value, so an identifier in its text was
        # invented (observed: a 7B typing "123456789012" for an Aadhaar field).
        raw = PII_TOKEN_RE.sub("", text)
        if RAW_ID_RE.search(raw) or verify_veiled([raw]):
            raise ActionRejected(
                "raw_pii_in_text",
                "your text contains an identifier value; you cannot know any PII value",
                f"Type the token instead, e.g. one of: {', '.join(sorted(ctx.vault)) or '(none on this frame)'}.",
            )

    signature = json.dumps(
        {"t": atype, "i": obj.get("index"), "x": obj.get("text"), "u": obj.get("url")},
        sort_keys=True,
    )
    recent = [h for h in ctx.history[-4:] if h.get("signature") == signature]
    noops = [h for h in recent if h.get("noop")]
    if len(noops) >= 2:
        raise ActionRejected(
            "repeated_noop",
            f"you have already tried this exact action {len(noops)} times and the page did not change",
            "Try a different element, scroll to reveal more of the page, or finish with what you have.",
        )
    # Changing pixels do not mean progress (a button that flashes and reverts).
    # Scrolling a long page legitimately repeats, so it is exempt.
    if atype != "scroll" and len(recent) >= 3:
        raise ActionRejected(
            "repeated_action",
            f"you have taken this exact action {len(recent)} times in your last 4 steps",
            "If the page shows the goal is done, use finish. Otherwise try something different.",
        )

    haystack = " ".join(
        str(x) for x in (mark.get("name") if mark else "", obj.get("text", ""), obj.get("reason", ""))
    )
    destructive = bool(DESTRUCTIVE_RE.search(haystack))
    state_changing = atype in {"click", "double_click", "type", "select_option", "navigate"}
    requires_confirmation = destructive and state_changing

    return ValidatedAction(
        action={**obj, "type": atype},
        mark=mark,
        signature=signature,
        requires_confirmation=requires_confirmation,
        risk="high" if requires_confirmation else ("medium" if state_changing else "low"),
    )


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"
