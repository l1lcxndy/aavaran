"""
AAVARAN — mock_vlm.py
=====================
An OpenAI-compatible /v1/chat/completions endpoint that returns SCRIPTED
actions instead of running a model.

WHY THIS EXISTS
---------------
As of right now there is no Qwen2.5-VL server running on your machine, which
means the ReAct loop — capture, veil, decide, validate, act — has never
executed end to end even once. That is the single largest untested surface in
the project, and the demo is hours away.

This lets you exercise the entire loop today: the extension captures, the veil
redacts, the delta encoder decides what to ship, main.py reconstructs the
frame, the validator gates the action, and the extension executes it. The only
thing being faked is the model's judgement.

HONESTY RULE
------------
Every response carries "model": "MOCK-SCRIPTED" and main.py logs it. If you
run the demo against this, you say so. "The perception and privacy pipeline is
live; the model's decisions are scripted because we could not fit a 7B VLM on
this laptop" is a completely respectable thing to tell a judge. Claiming a
model is reasoning when it is replaying a list is not, and it is the kind of
thing that unravels badly under one follow-up question.

RUN
---
    python -m uvicorn mock_vlm:app --host 127.0.0.1 --port 8001

Then point the brain at it:
    $env:AAVARAN_VLM_BASE = "http://127.0.0.1:8001/v1"
    python -m uvicorn main:app --host 127.0.0.1 --port 8756
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s  MOCK  %(message)s")
log = logging.getLogger("mock")

app = FastAPI(title="AAVARAN mock VLM")

# Latency band of a 7B VLM on a mid-range GPU. Included so your demo timings
# are honest rather than suspiciously instant.
SIMULATED_LATENCY_S = 0.9


class ChatRequest(BaseModel):
    model: str = ""
    messages: list[dict[str, Any]] = []
    temperature: float = 0.0
    max_tokens: int = 512
    response_format: dict[str, Any] | None = None


MARK_RE = re.compile(r"\[(\d+)\]\s+(input|button|link|select|combobox|listbox|\w+):\s*(.*)")


def parse_marks(text: str) -> list[dict[str, Any]]:
    """Read the MARKS block main.py renders into the observation."""
    marks = []
    for line in text.splitlines():
        m = MARK_RE.search(line.strip())
        if not m:
            continue
        marks.append({
            "id": int(m.group(1)),
            "kind": m.group(2),
            "name": m.group(3).strip(),
            "editable": m.group(2) == "input",
        })
    return marks


def find(marks: list[dict], *needles: str, editable: bool | None = None) -> dict | None:
    """Needles are tried in the order given, so the caller can put the most
    specific phrase first. Iterating marks on the outside instead would let an
    incidental early match beat a precise later one."""
    for needle in needles:
        for m in marks:
            if editable is not None and m["editable"] != editable:
                continue
            if needle.lower() in m["name"].lower():
                return m
    return None


def decide(goal: str, marks: list[dict], step: int, last_failed: bool) -> dict[str, Any]:
    """A small rule-based stand-in. Deliberately simple and deliberately
    capable of proposing something the validator will refuse, because a demo
    where the guardrail never fires proves nothing about the guardrail."""
    g = goal.lower()

    if step >= 6:
        return {"type": "finish", "summary": "Reached the step limit for this scripted run.",
                "success": False, "reason": "budget exhausted", "confidence": 0.4}

    # Statement download path
    if "statement" in g or "download" in g:
        if step == 0:
            t = find(marks, "statement")
            if t:
                return {"type": "click", "index": t["id"],
                        "reason": "Navigating to the statements section.", "confidence": 0.88}
        t = find(marks, "download")
        if t:
            return {"type": "click", "index": t["id"],
                    "reason": "Downloading the most recent statement.", "confidence": 0.91}
        # Target not marked yet: it is below the fold. A real VLM scrolls too.
        return {"type": "scroll", "direction": "down",
                "reason": "The download control is not visible; scrolling.", "confidence": 0.7}

    # Search / type path
    if "search" in g or "type" in g or "enter" in g:
        t = find(marks, "search", "query", editable=True)
        if t:
            return {"type": "type", "index": t["id"], "text": "quarterly report", "submit": True,
                    "reason": "Entering the search term.", "confidence": 0.85}

    # Transfer path — this one is SUPPOSED to get stopped. "Confirm and Pay"
    # matches DESTRUCTIVE_RE, so the validator returns requiresConfirmation
    # and the run halts for a human. That is the demo moment.
    #
    # Needles are ordered longest-first and restricted to non-editable marks:
    # a bare "pay" needle matches "Payee account number", which would click an
    # input instead of the button and silently skip the whole demonstration.
    if "transfer" in g or "pay" in g or "send" in g:
        t = find(marks, "confirm and pay", "confirm", "transfer", editable=False)
        if t:
            return {"type": "click", "index": t["id"],
                    "reason": "Submitting the transfer.", "confidence": 0.79}

    # Deliberate bad action, once, to show the whitelist rejecting and the
    # model self-repairing on the retry.
    if step == 1 and last_failed is False and "reject" in g:
        return {"type": "execute_script", "code": "document.forms[0].submit()",
                "reason": "Trying a shortcut.", "confidence": 0.6}

    if marks:
        clickable = [m for m in marks if not m["editable"]]
        if clickable:
            t = clickable[min(step, len(clickable) - 1)]
            return {"type": "click", "index": t["id"],
                    "reason": f"Exploring: {t['name'][:50]}", "confidence": 0.55}

    return {"type": "finish", "summary": "Nothing actionable on this page.",
            "success": False, "reason": "no marks", "confidence": 0.3}


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    return {"object": "list", "data": [{"id": "MOCK-SCRIPTED", "object": "model"}]}


@app.post("/v1/chat/completions")
async def chat(req: ChatRequest) -> dict[str, Any]:
    text_parts: list[str] = []
    for m in req.messages:
        c = m.get("content")
        if isinstance(c, str):
            text_parts.append(c)
        elif isinstance(c, list):
            text_parts.extend(p.get("text", "") for p in c if p.get("type") == "text")
    blob = "\n".join(text_parts)

    goal = ""
    step = 0
    gm = re.search(r"^GOAL:\s*(.+)$", blob, re.M)
    if gm:
        goal = gm.group(1).strip()
    sm = re.findall(r"^STEP:\s*(\d+)$", blob, re.M)
    if sm:
        step = int(sm[-1])

    last_failed = "PREVIOUS ACTION FAILED" in blob or "REJECTED (" in blob
    marks = parse_marks(blob)

    # If the transcript shows a rejection, repair rather than repeating. This
    # exercises main.py's self-repair loop for real.
    if "REJECTED (" in blob:
        rej = blob.rsplit("REJECTED (", 1)[1].split(")")[0]
        log.info("repairing after rejection: %s", rej)
        clickable = [m for m in marks if not m["editable"]]
        action = ({"type": "click", "index": clickable[0]["id"],
                   "reason": f"Recovering after {rej}.", "confidence": 0.7}
                  if clickable else
                  {"type": "finish", "summary": "Could not recover.", "success": False,
                   "reason": rej, "confidence": 0.3})
    else:
        action = decide(goal, marks, step, last_failed)

    log.info("goal=%r step=%d marks=%d -> %s", goal[:40], step, len(marks), action["type"])
    time.sleep(SIMULATED_LATENCY_S)

    body = json.dumps(action)
    return {
        "id": f"mock-{int(time.time() * 1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "MOCK-SCRIPTED",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": body},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": len(blob) // 4, "completion_tokens": len(body) // 4,
                  "total_tokens": (len(blob) + len(body)) // 4},
    }
