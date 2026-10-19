"""
AAVARAN — framestore.py
=======================
Server half of delta encoding.

Two separate jobs, deliberately not conflated:

  1. RECONSTRUCTION — keep an authoritative full-resolution frame per session
     so anything downstream (logging, the glass-box replay, a keyframe retry)
     always has a coherent screenshot, even on steps where only a 180x40 patch
     crossed the wire.

  2. VLM FRAMING — decide what actually enters the model's context. This is
     where the token saving lives, and it is NOT the same as what crossed the
     wire. On an unchanged frame we emit no image at all and let the previous
     turn's image carry the visual state; on a patch we emit the crop with a
     caption naming its position, because the model already holds the
     keyframe from an earlier turn.

Token arithmetic that motivates the policy, at egress 1536px and Qwen2.5-VL's
one visual token per 28x28 pixel block:

    full 1536x864 frame        1,620 image tokens
    patch 384x192                 78 image tokens
    unchanged                      0

A 20-step run that keyframes every 8 steps and patches the rest:
    3 x 1,620 + 17 x ~90  =  ~6,390   versus   20 x 1,620 = 32,400.
"""

from __future__ import annotations

import base64
import io
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from PIL import Image

Mode = Literal["full", "patch", "unchanged"]


@dataclass
class VlmFrame:
    """What to put in the model's context this turn."""
    image_b64: str | None          # None means: send no image, reuse prior turn
    caption: str
    kind: Mode
    width: int
    height: int
    est_tokens: int


@dataclass
class SessionFrames:
    full: Image.Image | None = None
    frame_id: str = ""
    step_of_last_keyframe: int = -999
    patches_since_keyframe: int = 0
    updated: float = field(default_factory=time.time)


class FrameStore:
    """Bounded, TTL'd. Frames are post-veil, but they are still screenshots of
    the user's session — they are not persisted to disk and they expire."""

    def __init__(self, ttl_seconds: int = 900, max_sessions: int = 64,
                 keyframe_every: int = 8, patch_budget: int = 12):
        self.ttl = ttl_seconds
        self.max_sessions = max_sessions
        self.keyframe_every = keyframe_every
        self.patch_budget = patch_budget
        self._s: dict[str, SessionFrames] = {}

    # ---------------------------------------------------------------- utils
    def _gc(self) -> None:
        now = time.time()
        dead = [k for k, v in self._s.items() if now - v.updated > self.ttl]
        for k in dead:
            self._s.pop(k, None)
        while len(self._s) > self.max_sessions:
            oldest = min(self._s.items(), key=lambda kv: kv[1].updated)[0]
            self._s.pop(oldest, None)

    def drop(self, session: str) -> None:
        self._s.pop(session, None)

    def _get(self, session: str) -> SessionFrames:
        self._gc()
        if session not in self._s:
            self._s[session] = SessionFrames()
        s = self._s[session]
        s.updated = time.time()
        return s

    # ------------------------------------------------------------- ingest
    def ingest(
        self,
        session: str,
        mode: Mode,
        image_b64: str | None,
        rect: list[int] | None,
        frame_id: str,
        step: int,
    ) -> tuple[Image.Image | None, str | None]:
        """Fold this step's bytes into the session's authoritative frame.

        Returns (full_frame, error). An error is never fatal to the run — the
        caller degrades to requesting a keyframe on the next step, which is
        strictly better than guessing at a corrupt reconstruction.
        """
        s = self._get(session)

        if mode == "unchanged":
            if s.full is None:
                return None, "no cached frame to reuse; keyframe required"
            s.frame_id = frame_id
            return s.full, None

        if image_b64 is None:
            return s.full, "image payload missing"

        try:
            img = Image.open(io.BytesIO(base64.b64decode(image_b64))).convert("RGB")
        except Exception as e:  # noqa: BLE001
            return s.full, f"decode failed: {e}"

        if mode == "full":
            s.full = img
            s.frame_id = frame_id
            s.step_of_last_keyframe = step
            s.patches_since_keyframe = 0
            return s.full, None

        # patch
        if s.full is None:
            return None, "patch received with no base frame; keyframe required"
        if not rect or len(rect) != 4:
            return s.full, "patch received without a rect"

        x, y, w, h = (int(v) for v in rect)
        if w <= 0 or h <= 0 or x < 0 or y < 0 or x + w > s.full.width or y + h > s.full.height:
            return s.full, f"patch rect {rect} outside frame {s.full.size}"
        if (img.width, img.height) != (w, h):
            img = img.resize((w, h), Image.LANCZOS)

        # Copy-on-write: the previous frame may still be referenced by an
        # in-flight log writer.
        base = s.full.copy()
        base.paste(img, (x, y))
        s.full = base
        s.frame_id = frame_id
        s.patches_since_keyframe += 1
        return s.full, None

    # ------------------------------------------------------- vlm framing
    def needs_keyframe(self, session: str, step: int, url_changed: bool) -> bool:
        s = self._get(session)
        if s.full is None:
            return True
        if url_changed:
            return True
        if step - s.step_of_last_keyframe >= self.keyframe_every:
            return True
        return s.patches_since_keyframe >= self.patch_budget

    def frame_for_vlm(
        self,
        session: str,
        mode: Mode,
        patch_b64: str | None,
        rect: list[int] | None,
        step: int,
        marks_in_patch: list[int] | None = None,
    ) -> VlmFrame:
        s = self._get(session)

        if mode == "unchanged":
            return VlmFrame(
                image_b64=None,
                caption=(
                    "The page is pixel-identical to the screenshot in the previous turn. "
                    "No new image is attached. Your last action produced no visible change."
                ),
                kind="unchanged",
                width=s.full.width if s.full else 0,
                height=s.full.height if s.full else 0,
                est_tokens=0,
            )

        if mode == "patch" and patch_b64 and rect and s.full is not None:
            x, y, w, h = rect
            where = _quadrant(x + w / 2, y + h / 2, s.full.width, s.full.height)
            marks_note = ""
            if marks_in_patch:
                ids = ", ".join(f"[{m}]" for m in sorted(marks_in_patch)[:24])
                marks_note = f" Marks inside this region: {ids}."
            return VlmFrame(
                image_b64=patch_b64,
                caption=(
                    f"Only part of the page changed. Attached is a {w}x{h} crop taken at "
                    f"({x}, {y}) — the {where} of the viewport. Everything outside this crop "
                    f"is unchanged from the full screenshot you were shown earlier, and the "
                    f"mark numbering is stable across both.{marks_note}"
                ),
                kind="patch",
                width=w,
                height=h,
                est_tokens=_est_tokens(w, h),
            )

        # A full-mode upload already IS the frame; re-encoding it costs ~100ms of PNG.
        if mode == "full" and patch_b64:
            full_b64 = patch_b64
        else:
            full_b64 = _encode(s.full) if s.full is not None else (patch_b64 or "")
        w = s.full.width if s.full else 0
        h = s.full.height if s.full else 0
        return VlmFrame(
            image_b64=full_b64,
            caption="Full current view of the page, with interactive elements numbered.",
            kind="full",
            width=w,
            height=h,
            est_tokens=_est_tokens(w, h),
        )

    def marks_in_rect(self, marks: list[dict[str, Any]], rect: list[int] | None) -> list[int]:
        if not rect:
            return [m["id"] for m in marks]
        x, y, w, h = rect
        out = []
        for m in marks:
            b = m.get("bbox") or [0, 0, 0, 0]
            if b[2] <= x or b[0] >= x + w or b[3] <= y or b[1] >= y + h:
                continue
            out.append(m["id"])
        return out

    def snapshot_b64(self, session: str) -> str | None:
        s = self._s.get(session)
        return _encode(s.full) if s and s.full else None


def _encode(img: Image.Image, fmt: str = "PNG") -> str:
    buf = io.BytesIO()
    img.save(buf, format=fmt, optimize=True)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _est_tokens(w: int, h: int) -> int:
    """Qwen2.5-VL: 14x14 ViT patches, 2x2 spatially merged before the LLM,
    i.e. one visual token per 28x28 pixel block."""
    if not w or not h:
        return 0
    return max(4, (w // 28) * (h // 28))


def _quadrant(cx: float, cy: float, w: int, h: int) -> str:
    v = "top" if cy < h / 3 else ("bottom" if cy > 2 * h / 3 else "middle")
    hz = "left" if cx < w / 3 else ("right" if cx > 2 * w / 3 else "centre")
    return f"{v}-{hz}"
