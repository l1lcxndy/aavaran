"""
AAVARAN — main.py
=================
The Brain. FastAPI + an OpenAI-compatible VLM endpoint (vLLM, DashScope,
Ollama, LM Studio — anything that speaks /v1/chat/completions).

What changed for the hardening pass:

  * /act accepts a delta observation. On an unchanged frame it sends the model
    zero image tokens; on a patch it sends the crop with a positional caption;
    it forces a keyframe on URL change, every N steps, or when reconstruction
    reports an error.

  * Context is a sliding window over images, not over turns. Old turns keep
    their text (the reasoning trace, which is cheap and load-bearing) and drop
    their images (expensive and superseded). This is what stops a 30-step run
    from blowing the context window.

  * Every proposal passes actions.validate() before it leaves this process.
    A rejection is fed back as a repair turn rather than ending the run.

  * The system prefix is byte-stable across the whole run so upstream prompt
    caching can actually hit.

Run:  uvicorn main:app --host 127.0.0.1 --port 8756 --reload
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import actions as A
from framestore import FrameStore
from store import JsonlAudit, MemoryStore, PostgresAudit, RedisStore
from veil_check import verify_veiled

logging.basicConfig(
    level=os.getenv("AAVARAN_LOG", "INFO"),
    format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
)
log = logging.getLogger("aavaran")

VLM_BASE = os.getenv("AAVARAN_VLM_BASE", "http://127.0.0.1:8000/v1")
VLM_MODEL = os.getenv("AAVARAN_VLM_MODEL", "Qwen/Qwen2.5-VL-7B-Instruct")
VLM_KEY = os.getenv("AAVARAN_VLM_KEY", "not-needed")
VLM_TIMEOUT = float(os.getenv("AAVARAN_VLM_TIMEOUT", "90"))
MAX_REPAIRS = int(os.getenv("AAVARAN_MAX_REPAIRS", "2"))
MAX_IMAGES_IN_CONTEXT = int(os.getenv("AAVARAN_MAX_IMAGES", "3"))
KEYFRAME_EVERY = int(os.getenv("AAVARAN_KEYFRAME_EVERY", "8"))
AUDIT_LOG = os.getenv("AAVARAN_AUDIT_LOG", "audit.jsonl")
AUDIT_DSN = os.getenv("AAVARAN_AUDIT_DSN", "")    # postgresql://... enables the Postgres sink
REDIS_URL = os.getenv("AAVARAN_REDIS_URL", "")    # redis://... persists sessions across restarts
SESSION_TTL = int(os.getenv("AAVARAN_SESSION_TTL", "900"))

# Actions that should visibly change the page. Typing into a field may not move
# the coarse dHash, so it is never adjudicated as a no-op.
VISIBLE_ACTIONS = {"click", "double_click", "scroll", "go_back", "navigate"}

@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _http, STORE, AUDIT
    _http = httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=8))
    if REDIS_URL:
        STORE = RedisStore.from_url(REDIS_URL, _decode_session, ttl=SESSION_TTL)
    if AUDIT_DSN:
        AUDIT = PostgresAudit(AUDIT_DSN, fallback=JsonlAudit(AUDIT_LOG))
    await AUDIT.start()
    log.info("AAVARAN up. VLM=%s @ %s · sessions=%s audit=%s",
             VLM_MODEL, VLM_BASE, type(STORE).__name__, type(AUDIT).__name__)
    yield
    await _http.aclose()


app = FastAPI(title="AAVARAN", version="0.4.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    # The extension's origin is chrome-extension://<32 chars>, which changes
    # between an unpacked load and a packed build. Regex, not a literal.
    allow_origin_regex=r"chrome-extension://[a-p]{32}|http://localhost:\d+",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=600,
)

frames = FrameStore(keyframe_every=KEYFRAME_EVERY)
_http: httpx.AsyncClient | None = None


class Mark(BaseModel):
    id: int
    role: str = ""
    name: str = ""
    editable: bool = False
    bbox: list[float] = Field(default_factory=list)
    options: list[str] | None = None
    stableKey: str | None = None


class Delta(BaseModel):
    mode: Literal["full", "patch", "unchanged"] = "full"
    frameId: str = ""
    baseFrameId: str | None = None
    rect: list[int] | None = None       # x, y, w, h in egress px
    changeRatio: float = 1.0
    reason: str = ""
    width: int = 0
    height: int = 0


class VeilReport(BaseModel):
    mode: str = "unknown"
    ocr: bool = False
    faces: bool = False
    profile: str = "strict"
    textRegions: int = 0
    faceRegions: int = 0
    failClosedRegions: int = 0
    warnings: list[str] = Field(default_factory=list)


class LastResult(BaseModel):
    ok: bool = True
    error: str | None = None
    noop: bool = False          # pixel hash + mark signature both unchanged


class Observation(BaseModel):
    session: str
    goal: str
    step: int = 0
    url: str = ""
    title: str = ""
    image: str | None = None    # base64 PNG, full frame or patch
    delta: Delta = Field(default_factory=Delta)
    marks: list[Mark] = Field(default_factory=list)
    pixelHash: str = ""
    markSignature: str = ""
    veil: VeilReport = Field(default_factory=VeilReport)
    vault: dict[str, dict[str, Any]] = Field(default_factory=dict)
    navAllowlist: list[str] = Field(default_factory=list)
    lastResult: LastResult | None = None


class ActResponse(BaseModel):
    ok: bool
    action: dict[str, Any] | None = None
    reasoning: str = ""
    confidence: float = 0.0
    requiresConfirmation: bool = False
    risk: str = "low"
    done: bool = False
    needsKeyframe: bool = False
    repairs: int = 0
    tokens: dict[str, int] = Field(default_factory=dict)
    latencyMs: int = 0
    error: str | None = None
    # HMAC-SHA256 (per-session key from /session) over `envelope`, the exact
    # JSON the client parses its action from. Binds the action to session+step.
    envelope: str | None = None
    signature: str | None = None


@dataclass
class Turn:
    role: str
    text: str
    image_b64: str | None = None
    step: int = 0
    kind: str = ""            # full | patch | unchanged (user turns with frames)
    had_image: bool = False   # image dropped from memory: outside the context window


@dataclass
class Session:
    id: str
    goal: str = ""
    key: str = ""             # per-session HMAC signing key (hex)
    turns: list[Turn] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    last_url: str = ""
    last_pixel_hash: str = ""
    last_mark_signature: str = ""
    created: float = field(default_factory=time.time)
    touched: float = field(default_factory=time.time)


def _decode_session(d: dict[str, Any]) -> Session:
    return Session(**{**d, "turns": [Turn(**t) for t in d.get("turns", [])]})


STORE: Any = MemoryStore()
AUDIT: Any = JsonlAudit(AUDIT_LOG)
# Per-process: one step at a time per session. With several server workers,
# route a session to one worker (sticky); the client is sequential anyway.
_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


async def session_for(obs: Observation) -> Session | None:
    s = await STORE.get(obs.session)
    if s is None:
        return None          # no /session handshake (or it expired): no signing key
    if s.goal != obs.goal:
        s = Session(id=obs.session, goal=obs.goal, key=s.key)
        frames.drop(obs.session)
    s.touched = time.time()
    return s


def _image_window(s: Session) -> set[int]:
    """Turns whose image goes to the model: the last MAX_IMAGES_IN_CONTEXT,
    plus always the latest keyframe, which every later patch is relative to."""
    with_img = [i for i, t in enumerate(s.turns) if t.image_b64]
    keep = set(with_img[-MAX_IMAGES_IN_CONTEXT:])
    fulls = [i for i in with_img if s.turns[i].kind == "full"]
    if fulls:
        keep.add(fulls[-1])
    return keep


def prune_images(s: Session) -> None:
    """Drop image bytes the context window will never send again."""
    keep = _image_window(s)
    for i, t in enumerate(s.turns):
        if t.image_b64 and i not in keep:
            t.image_b64 = None
            t.had_image = True


# Byte-stable across the whole run: never interpolate the goal, step count or
# timestamp into this string, or every request misses the upstream prompt cache
# and you pay full price for the prefix on all 30 steps.
SYSTEM_PROMPT = f"""You are AAVARAN, a browser agent that operates through a privacy veil.

WHAT YOU SEE
Screenshots are redacted before they reach you. Solid black bars are destroyed
pixels — that data no longer exists in the image. Where a bar carries a label
like <PII:AADHAAR#1>, you may REFERENCE that value by its token (for example,
to type it into a field) without ever knowing it. Treat tokens as opaque
handles. Never guess, reconstruct, or ask for the value behind a token.

Interactive elements are outlined and numbered. Cyan = clickable.
Yellow = editable text field. You act by citing a number, never a coordinate.

DELTA FRAMES
To save time, some turns attach only a cropped region of the page instead of
the whole view, or no image at all. When that happens the caption tells you so.
Everything outside a crop is unchanged from the last full screenshot, and the
numbering of marks is stable across frames: [14] is the same element in every
turn of this run.

HOW TO ACT
Think briefly, then emit exactly one action.
{A.schema_text()}

RULES
- One action per turn. No batching.
- If the page did not change after your last action, do not repeat it — the
  element was probably not the one you wanted, or the page needs scrolling.
- If you need information that is redacted, or a decision only the user can
  make, use ask_user.
- If the goal is achieved, or cannot be achieved, use finish.

OUTPUT FORMAT
Reply with a single JSON object and nothing else."""


def observation_text(obs: Observation, caption: str) -> str:
    lines = [f"GOAL: {obs.goal}", f"STEP: {obs.step}", f"URL: {obs.url}"]
    if obs.title:
        lines.append(f"TITLE: {obs.title}")
    lines.append("")
    lines.append(caption)

    if obs.lastResult:
        if not obs.lastResult.ok:
            lines.append(f"PREVIOUS ACTION FAILED: {obs.lastResult.error}")
        elif obs.lastResult.noop:
            lines.append("PREVIOUS ACTION PRODUCED NO VISIBLE CHANGE.")

    v = obs.veil
    veil_bits = [f"profile={v.profile}", f"ocr={'on' if v.ocr else 'FAILED'}"]
    if v.textRegions or v.faceRegions or v.failClosedRegions:
        veil_bits.append(
            f"destroyed {v.textRegions} text, {v.faceRegions} face, "
            f"{v.failClosedRegions} precautionary regions"
        )
    if not v.ocr:
        veil_bits.append("text redaction unavailable — treat any unlabelled "
                         "black region as possibly-sensitive")
    lines.append("VEIL: " + " · ".join(veil_bits))

    if obs.vault:
        lines.append("TOKENS AVAILABLE: " + ", ".join(sorted(obs.vault)))

    # The manifest is the model's index space. Including it as text costs ~8
    # tokens per mark but removes the entire "misread the chip" failure mode,
    # which is by far the more expensive error.
    lines.append("")
    lines.append("MARKS:")
    for m in obs.marks[:120]:
        kind = "input" if m.editable else m.role or "element"
        name = (m.name or "").strip().replace("\n", " ")[:70]
        opts = f" options={m.options[:8]}" if m.options else ""
        lines.append(f"  [{m.id}] {kind}: {name}{opts}")
    return "\n".join(lines)


def build_messages(s: Session) -> list[dict[str, Any]]:
    """Sliding window over IMAGES, not over turns."""
    msgs: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    keep = _image_window(s)

    for i, t in enumerate(s.turns):
        if t.role == "assistant":
            msgs.append({"role": "assistant", "content": t.text})
            continue
        if t.image_b64 and i in keep:
            msgs.append({
                "role": "user",
                "content": [
                    {"type": "image_url",
                     "image_url": {"url": f"data:image/png;base64,{t.image_b64}"}},
                    {"type": "text", "text": t.text},
                ],
            })
        else:
            omitted = t.image_b64 or t.had_image
            prefix = "[screenshot from this step omitted to save context]\n" if omitted else ""
            msgs.append({"role": "user", "content": prefix + t.text})
    return msgs


# Strongest output constraint this VLM server accepts, learned on first use:
# 0 = json_schema (vLLM + XGrammar), 1 = json_object, 2 = unconstrained.
_rf_level = 0


def _response_format(level: int, schema: dict[str, Any]) -> dict[str, Any] | None:
    if level == 0:
        return {"type": "json_schema",
                "json_schema": {"name": "action", "schema": schema, "strict": True}}
    if level == 1:
        return {"type": "json_object"}
    return None


async def call_vlm(messages: list[dict[str, Any]], schema: dict[str, Any]) -> tuple[str, dict[str, int]]:
    global _rf_level
    assert _http is not None
    level = _rf_level
    while True:
        payload: dict[str, Any] = {
            "model": VLM_MODEL,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 512,
        }
        rf = _response_format(level, schema)
        if rf:
            payload["response_format"] = rf
        r = await _http.post(
            f"{VLM_BASE}/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {VLM_KEY}"},
            timeout=VLM_TIMEOUT,
        )
        # Not every server supports structured output; step down a level
        # rather than failing the step. Only a success is remembered, so a 400
        # for another reason (context length) does not degrade later calls.
        if r.status_code in (400, 422) and level < 2:
            log.warning("VLM rejected response_format level %d (%s); trying %d",
                        level, r.text[:120], level + 1)
            level += 1
            continue
        if r.status_code >= 400:
            raise RuntimeError(f"VLM {r.status_code}: {r.text[:400]}")
        _rf_level = level
        break
    data = r.json()
    text = data["choices"][0]["message"]["content"]
    usage = data.get("usage") or {}
    return text, {
        "prompt": usage.get("prompt_tokens", 0),
        "completion": usage.get("completion_tokens", 0),
        "cached": (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
    }


@app.get("/health")
@app.get("/healthz")
async def health() -> dict[str, Any]:
    return {"ok": True, "model": VLM_MODEL, "sessions": await STORE.count()}


@app.get("/preflight")
@app.post("/preflight")
async def preflight() -> dict[str, Any]:
    """The extension's Preflight button hits this. It failed in your logs
    because there was nothing on the other end — the panel reported
    AAVARAN_PREFLIGHT failed without distinguishing 'server down' from
    'assets broken'. Now it can."""
    reachable, detail = False, ""
    try:
        assert _http is not None
        r = await _http.get(f"{VLM_BASE}/models",
                            headers={"Authorization": f"Bearer {VLM_KEY}"}, timeout=5)
        reachable = r.status_code < 400
        detail = f"HTTP {r.status_code}"
    except Exception as e:  # noqa: BLE001
        detail = str(e)
    return {
        "ok": reachable,
        "server": "up",
        "vlm": {"reachable": reachable, "base": VLM_BASE, "model": VLM_MODEL, "detail": detail},
        "policy": {
            "keyframeEvery": KEYFRAME_EVERY,
            "maxImagesInContext": MAX_IMAGES_IN_CONTEXT,
            "maxRepairs": MAX_REPAIRS,
            "allowedActions": sorted(A.ACTION_SPECS),
        },
    }


@app.post("/session/{session_id}/reset")
async def reset(session_id: str) -> dict[str, bool]:
    await STORE.drop(session_id)
    frames.drop(session_id)
    return {"ok": True}


from fastapi import Request as _Request

@app.post("/session")
async def start_session(request: _Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    # openServerSession() in background.js reads response.session_id and has
    # nothing to fall back to, so this must never come back empty.
    sid = body.get("session") or body.get("sessionId") or body.get("id") or uuid.uuid4().hex
    key = secrets.token_hex(32)
    await STORE.put(Session(id=sid, goal=str(body.get("goal") or ""), key=key))
    frames.drop(sid)
    # The key travels once, at session start; every /act response is signed
    # with it so the client can reject an action it did not get from us.
    return {"ok": True, "session_id": sid, "session": sid, "signing_key": key}

async def audit(obs: Observation, leaks: list[str]) -> None:
    """Append-only record of exactly what crossed the wire (DPDP audit trail).
    Hashes and sizes only; the frame itself is never written to disk."""
    raw = base64.b64decode(obs.image) if obs.image else b""
    await AUDIT.write({
        "ts": time.time(), "session": obs.session, "step": obs.step, "url": obs.url,
        "image_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "image_bytes": len(raw), "delta": obs.delta.mode, "marks": len(obs.marks),
        "tokens": sorted(obs.vault), "veil": obs.veil.mode, "leaks": leaks,
    })


def sign(s: Session, obs: Observation, action: dict[str, Any]) -> tuple[str, str]:
    envelope = json.dumps({"session": obs.session, "step": obs.step, "action": action},
                          ensure_ascii=False)
    sig = hmac.new(bytes.fromhex(s.key), envelope.encode("utf-8"), hashlib.sha256).hexdigest()
    return envelope, sig


@app.post("/act", response_model=ActResponse)
async def act(obs: Observation) -> ActResponse:
    t0 = time.perf_counter()

    leaks = verify_veiled([obs.goal, obs.url, obs.title, *(m.name for m in obs.marks)])
    await audit(obs, leaks)
    if leaks:
        log.error("[%s] raw PII in observation text: %s", obs.session[:8], leaks)
        return ActResponse(ok=False, error=f"veil_check_failed: raw {', '.join(leaks)} in text fields")

    # One step at a time per session: a double-click on Run would interleave two steps.
    async with _locks[obs.session]:
        s = await session_for(obs)
        if s is None:
            return ActResponse(ok=False, error="unknown_session: open one with POST /session")
        try:
            return await _act_step(obs, s, t0)
        finally:
            prune_images(s)
            await STORE.put(s)


async def _act_step(obs: Observation, s: Session, t0: float) -> ActResponse:
    url_changed = bool(s.last_url) and obs.url != s.last_url

    # The server adjudicates whether the previous action moved the world.
    prev = s.history[-1] if s.history else None
    if obs.lastResult and prev and prev["type"] in VISIBLE_ACTIONS and s.last_pixel_hash:
        obs.lastResult.noop = obs.lastResult.noop or (
            obs.pixelHash == s.last_pixel_hash and obs.markSignature == s.last_mark_signature
        )

    full, ingest_err = frames.ingest(
        session=obs.session,
        mode=obs.delta.mode,
        image_b64=obs.image,
        rect=obs.delta.rect,
        frame_id=obs.delta.frameId or uuid.uuid4().hex,
        step=obs.step,
    )
    if ingest_err:
        log.warning("[%s] frame ingest: %s", obs.session[:8], ingest_err)
        return ActResponse(
            ok=False, needsKeyframe=True, error=ingest_err,
            latencyMs=int((time.perf_counter() - t0) * 1000),
        )

    vf = frames.frame_for_vlm(
        session=obs.session,
        mode=obs.delta.mode,
        patch_b64=obs.image,
        rect=obs.delta.rect,
        step=obs.step,
        marks_in_patch=frames.marks_in_rect(
            [m.model_dump() for m in obs.marks], obs.delta.rect
        ) if obs.delta.mode == "patch" else None,
    )

    text = observation_text(obs, vf.caption)
    s.turns.append(Turn(role="user", text=text, image_b64=vf.image_b64, step=obs.step, kind=vf.kind))

    ctx = A.ValidationContext(
        url=obs.url,
        marks=[m.model_dump() for m in obs.marks],
        vault=obs.vault,
        nav_allowlist=obs.navAllowlist,
        history=s.history,
        step=obs.step,
    )

    tokens = {"prompt": 0, "completion": 0, "cached": 0, "image_est": vf.est_tokens}
    repairs = 0
    validated: A.ValidatedAction | None = None
    raw_text = ""
    last_err: A.ActionRejected | None = None

    for attempt in range(MAX_REPAIRS + 1):
        try:
            raw_text, usage = await call_vlm(build_messages(s), A.json_schema(m.id for m in obs.marks))
        except Exception as e:  # noqa: BLE001
            log.exception("VLM call failed")
            s.turns.pop()
            return ActResponse(
                ok=False, error=f"vlm_unreachable: {e}",
                latencyMs=int((time.perf_counter() - t0) * 1000),
            )
        for k in ("prompt", "completion", "cached"):
            tokens[k] += usage.get(k, 0)

        try:
            validated = A.validate(raw_text, ctx)
            break
        except A.ActionRejected as e:
            last_err = e
            repairs += 1
            log.info("[%s] step %d rejected (%s): %s",
                     obs.session[:8], obs.step, e.code, e.detail)
            if attempt >= MAX_REPAIRS:
                break
            # The rejection goes into the transcript so the model can see
            # its own bad output next to the reason. Re-prompting without
            # the offending output roughly halves the repair rate.
            s.turns.append(Turn(role="assistant", text=raw_text, step=obs.step))
            s.turns.append(Turn(role="user", text=e.repair_prompt(), step=obs.step))

    if validated is None:
        s.turns.append(Turn(
            role="user",
            text=f"(the agent could not produce a valid action: {last_err})",
            step=obs.step,
        ))
        return ActResponse(
            ok=False, repairs=repairs, tokens=tokens,
            error=f"validation_exhausted: {last_err}",
            latencyMs=int((time.perf_counter() - t0) * 1000),
        )

    s.turns.append(Turn(role="assistant", text=raw_text, step=obs.step))

    act_obj = validated.action
    reasoning = str(act_obj.get("reason") or "")[:500]
    confidence = float(act_obj.get("confidence") or 0.0)

    s.history.append({
        "step": obs.step,
        "signature": validated.signature,
        "type": act_obj["type"],
        "index": act_obj.get("index"),
        "noop": False,           # the extension reports this back next step
    })
    # Attribute the previous step's no-op to the previous entry, which is
    # what the loop breaker reads.
    if obs.lastResult and obs.lastResult.noop and len(s.history) >= 2:
        s.history[-2]["noop"] = True

    s.last_url = obs.url
    s.last_pixel_hash = obs.pixelHash
    s.last_mark_signature = obs.markSignature

    need_kf = frames.needs_keyframe(obs.session, obs.step + 1, url_changed)

    log.info(
        "[%s] step %d  %s  mode=%s(%.1f%%)  img~%d tok  prompt=%d (cached %d)  repairs=%d  %dms",
        obs.session[:8], obs.step, act_obj["type"], obs.delta.mode,
        obs.delta.changeRatio * 100, vf.est_tokens,
        tokens["prompt"], tokens["cached"], repairs,
        int((time.perf_counter() - t0) * 1000),
    )

    envelope, signature = sign(s, obs, act_obj)
    return ActResponse(
        ok=True,
        action=act_obj,
        envelope=envelope,
        signature=signature,
        reasoning=reasoning,
        confidence=confidence,
        requiresConfirmation=validated.requires_confirmation,
        risk=validated.risk,
        done=act_obj["type"] in {"finish", "ask_user"},
        needsKeyframe=need_kf,
        repairs=repairs,
        tokens=tokens,
        latencyMs=int((time.perf_counter() - t0) * 1000),
    )


@app.exception_handler(Exception)
async def _unhandled(_req, exc: Exception) -> JSONResponse:
    log.exception("unhandled")
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


