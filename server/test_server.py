"""End-to-end tests for the brain, against the real scripted mock VLM (in-process).

    cd server && python -m pytest -q
"""

import asyncio
import base64
import hashlib
import hmac
import io
import json

import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image

import main
import mock_vlm
from store import JsonlAudit, PostgresAudit, RedisStore

MARKS = [
    {"id": 1, "role": "textbox:text", "name": "Aadhaar", "editable": True, "bbox": [0, 0, 40, 20]},
    {"id": 7, "role": "button", "name": "Next", "bbox": [0, 30, 40, 50]},
]


def png(w=64, h=48, color="white"):
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, "PNG")
    return base64.b64encode(buf.getvalue()).decode()


class Recorder(httpx.AsyncBaseTransport):
    """Forwards to the mock VLM app; records requests; can reject json_schema."""

    def __init__(self, reject_schema=False):
        self.inner = httpx.ASGITransport(app=mock_vlm.app)
        self.reject_schema = reject_schema
        self.bodies = []

    async def handle_async_request(self, request):
        body = json.loads(request.content or b"{}")
        self.bodies.append(body)
        rf = body.get("response_format") or {}
        if self.reject_schema and rf.get("type") == "json_schema":
            return httpx.Response(400, json={"error": "json_schema response_format not supported"})
        return await self.inner.handle_async_request(request)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(mock_vlm, "SIMULATED_LATENCY_S", 0)
    monkeypatch.setattr(main, "AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "_rf_level", 0)
    with TestClient(main.app) as c:
        main.STORE = main.MemoryStore() if not isinstance(main.STORE, main.MemoryStore) else main.STORE
        main.AUDIT = JsonlAudit(str(tmp_path / "audit.jsonl"))
        rec = Recorder()
        main._http = httpx.AsyncClient(transport=rec, base_url="http://vlm")
        c.rec = rec
        yield c


def obs(sid, step, goal="explore", **kw):
    return {"session": sid, "goal": goal, "step": step, "url": "https://bank.example/kyc",
            "image": png(), "marks": MARKS, "pixelHash": "h", "markSignature": "m", **kw}


def open_session(c, goal="explore"):
    r = c.post("/session", json={"goal": goal}).json()
    assert len(r["signing_key"]) == 64
    return r["session_id"], bytes.fromhex(r["signing_key"])


def test_actions_are_signed_over_the_envelope(client):
    sid, key = open_session(client)
    r = client.post("/act", json=obs(sid, 0)).json()
    assert r["ok"], r
    expect = hmac.new(key, r["envelope"].encode(), hashlib.sha256).hexdigest()
    assert r["signature"] == expect
    env = json.loads(r["envelope"])
    assert env == {"session": sid, "step": 0, "action": r["action"]}


def test_unknown_session_is_refused(client):
    r = client.post("/act", json=obs("never-opened", 0)).json()
    assert not r["ok"] and r["error"].startswith("unknown_session")


def test_schema_constrains_index_to_visible_marks(client):
    sid, _ = open_session(client)
    client.post("/act", json=obs(sid, 0))
    rf = client.rec.bodies[-1]["response_format"]
    assert rf["type"] == "json_schema"
    click = next(v for v in rf["json_schema"]["schema"]["anyOf"]
                 if v["properties"]["type"] == {"const": "click"})
    assert click["properties"]["index"] == {"enum": [1, 7]}
    assert click["additionalProperties"] is False


def test_response_format_falls_back_and_remembers(client):
    client.rec.reject_schema = True
    sid, _ = open_session(client)
    assert client.post("/act", json=obs(sid, 0)).json()["ok"]
    assert [b.get("response_format", {}).get("type") for b in client.rec.bodies] == ["json_schema", "json_object"]
    assert main._rf_level == 1
    client.post("/act", json=obs(sid, 1, lastResult={"ok": True}))
    assert client.rec.bodies[-1]["response_format"]["type"] == "json_object"


def test_destructive_click_requires_confirmation(client):
    sid, _ = open_session(client, "pay the bill")
    marks = [MARKS[0], {"id": 2, "role": "button", "name": "Confirm and Pay", "bbox": [0, 0, 9, 9]}]
    r = client.post("/act", json=obs(sid, 0, goal="pay the bill", marks=marks)).json()
    assert r["action"]["type"] == "click" and r["action"]["index"] == 2
    assert r["requiresConfirmation"] and r["risk"] == "high"


def test_raw_pii_in_text_is_refused_and_audited(client, tmp_path):
    sid, _ = open_session(client)
    r = client.post("/act", json=obs(sid, 0, title="Statement for rahul@example.com")).json()
    assert not r["ok"] and "EMAIL" in r["error"]
    rec = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert rec["leaks"] == ["EMAIL"] and rec["image_bytes"] > 0 and "rahul" not in json.dumps(rec)


def test_noop_loop_breaker_fires(client):
    sid, _ = open_session(client)
    client.post("/act", json=obs(sid, 0))
    for step in (1, 2):
        assert client.post("/act", json=obs(sid, step, lastResult={"ok": True})).json()["ok"]
    r = client.post("/act", json=obs(sid, 3, lastResult={"ok": True})).json()
    assert not r["ok"] and "repeated_noop" in r["error"]


def test_unchanged_delta_sends_no_new_image(client):
    sid, _ = open_session(client)
    client.post("/act", json=obs(sid, 0))
    r = client.post("/act", json=obs(sid, 1, image=None, delta={"mode": "unchanged"},
                                     lastResult={"ok": True})).json()
    assert r["ok"], r
    last_user = client.rec.bodies[-1]["messages"][-1]
    assert isinstance(last_user["content"], str) and "pixel-identical" in last_user["content"]


def test_patch_without_base_frame_asks_for_keyframe(client):
    sid, _ = open_session(client)
    r = client.post("/act", json=obs(sid, 0, image=png(8, 8), delta={"mode": "patch", "rect": [0, 0, 8, 8]})).json()
    assert not r["ok"] and r["needsKeyframe"]


def test_redis_store_survives_restart(client):
    fake = fakeredis.aioredis.FakeRedis()
    main.STORE = RedisStore(fake, main._decode_session)
    try:
        sid, key = open_session(client)
        assert client.post("/act", json=obs(sid, 0)).json()["ok"]
        main.frames.drop(sid)                       # a restart loses frames, not sessions
        r = client.post("/act", json=obs(sid, 1, image=png(8, 8),
                                         delta={"mode": "patch", "rect": [0, 0, 8, 8]})).json()
        assert r["needsKeyframe"]                   # client resends a keyframe
        r = client.post("/act", json=obs(sid, 1, lastResult={"ok": True})).json()
        assert r["ok"]
        assert hmac.new(key, r["envelope"].encode(), hashlib.sha256).hexdigest() == r["signature"]
        s = asyncio.run(main.STORE.get(sid))
        assert s.key == key.hex() and len(s.history) == 2
    finally:
        main.STORE = main.MemoryStore()


def test_old_images_are_pruned_but_last_keyframe_kept():
    s = main.Session(id="x")
    s.turns.append(main.Turn("user", "k", image_b64="KEY", kind="full"))
    for i in range(5):
        s.turns.append(main.Turn("user", f"p{i}", image_b64=f"P{i}", kind="patch"))
    main.prune_images(s)
    kept = [t.image_b64 for t in s.turns if t.image_b64]
    assert kept == ["KEY", "P2", "P3", "P4"]
    assert all(t.had_image for t in s.turns if not t.image_b64)


def test_postgres_audit_inserts_and_falls_back(tmp_path):
    calls = []

    class Conn:
        closed = False

        async def execute(self, sql, params=None):
            if params and params[0] == "boom":
                raise RuntimeError("db down")
            calls.append((sql.split()[0], params))

    async def connect(dsn, autocommit):
        return Conn()

    fb = JsonlAudit(str(tmp_path / "fb.jsonl"))
    sink = PostgresAudit("postgresql://x", fallback=fb, connect=connect)
    rec = {"session": "s", "step": 1, "url": "u", "image_sha256": "h", "image_bytes": 3,
           "delta": "full", "marks": 2, "tokens": ["<PII:PAN#1>"], "veil": "full", "leaks": []}
    asyncio.run(sink.start())
    asyncio.run(sink.write(rec))
    asyncio.run(sink.write({**rec, "session": "boom"}))
    assert [c[0] for c in calls] == ["CREATE", "INSERT"]
    assert calls[1][1][7] == '["<PII:PAN#1>"]'
    assert json.loads((tmp_path / "fb.jsonl").read_text())["session"] == "boom"
