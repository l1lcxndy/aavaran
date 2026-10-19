"""
AAVARAN — store.py
==================
Where sessions and the egress audit trail live.

  sessions   in-process dict, or Redis when AAVARAN_REDIS_URL is set
             (survives a server restart; frames are NOT persisted — the
             client resends a keyframe when the server asks for one)
  audit      JSONL file, or Postgres when AAVARAN_AUDIT_DSN is set
             (falls back to JSONL on a write error so no record is lost)

Neither ever holds a PII value: sessions carry veiled frames and tokens,
audit rows carry hashes, sizes and token names.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from typing import Any, Callable

log = logging.getLogger("aavaran.store")


class MemoryStore:
    def __init__(self) -> None:
        self._d: dict[str, Any] = {}

    async def get(self, sid: str) -> Any:
        return self._d.get(sid)

    async def put(self, s: Any) -> None:
        self._d[s.id] = s

    async def drop(self, sid: str) -> None:
        self._d.pop(sid, None)

    async def count(self) -> int:
        return len(self._d)


class RedisStore:
    PREFIX = "aavaran:session:"

    def __init__(self, client: Any, decode: Callable[[dict[str, Any]], Any], ttl: int = 900) -> None:
        self.r = client
        self.decode = decode
        self.ttl = ttl

    @classmethod
    def from_url(cls, url: str, decode: Callable[[dict[str, Any]], Any], ttl: int = 900) -> "RedisStore":
        import redis.asyncio as redis
        return cls(redis.from_url(url), decode, ttl)

    async def get(self, sid: str) -> Any:
        raw = await self.r.get(self.PREFIX + sid)
        return self.decode(json.loads(raw)) if raw else None

    async def put(self, s: Any) -> None:
        await self.r.set(self.PREFIX + s.id, json.dumps(asdict(s)), ex=self.ttl)

    async def drop(self, sid: str) -> None:
        await self.r.delete(self.PREFIX + sid)

    async def count(self) -> int:
        n = 0
        async for _ in self.r.scan_iter(self.PREFIX + "*"):
            n += 1
        return n


class JsonlAudit:
    def __init__(self, path: str) -> None:
        self.path = path

    async def start(self) -> None:
        pass

    async def write(self, rec: dict[str, Any]) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError as e:
            log.warning("audit log write failed: %s", e)


class PostgresAudit:
    DDL = """CREATE TABLE IF NOT EXISTS egress_audit (
        id BIGSERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT now(),
        session TEXT NOT NULL,
        step INT NOT NULL,
        url TEXT,
        image_sha256 TEXT,
        image_bytes INT,
        delta TEXT,
        marks INT,
        tokens JSONB,
        veil TEXT,
        leaks JSONB
    )"""
    INSERT = """INSERT INTO egress_audit
        (session, step, url, image_sha256, image_bytes, delta, marks, tokens, veil, leaks)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

    def __init__(self, dsn: str, fallback: JsonlAudit, connect: Callable[..., Any] | None = None) -> None:
        self.dsn = dsn
        self.fallback = fallback
        self._connect = connect
        self.conn: Any = None
        self.lock = asyncio.Lock()   # one psycopg connection is not safe across tasks

    async def _conn(self) -> Any:
        if self.conn is None or self.conn.closed:
            connect = self._connect
            if connect is None:
                import psycopg
                connect = psycopg.AsyncConnection.connect
            self.conn = await connect(self.dsn, autocommit=True)
            await self.conn.execute(self.DDL)
        return self.conn

    async def start(self) -> None:
        try:
            async with self.lock:
                await self._conn()
        except Exception as e:  # noqa: BLE001
            log.error("postgres audit unavailable (%s); writing JSONL until it returns", e)

    async def write(self, rec: dict[str, Any]) -> None:
        params = (
            rec["session"], rec["step"], rec["url"], rec["image_sha256"], rec["image_bytes"],
            rec["delta"], rec["marks"], json.dumps(rec["tokens"]), rec["veil"], json.dumps(rec["leaks"]),
        )
        try:
            async with self.lock:
                await (await self._conn()).execute(self.INSERT, params)
        except Exception as e:  # noqa: BLE001
            log.warning("postgres audit write failed (%s); record kept in JSONL", e)
            self.conn = None
            await self.fallback.write(rec)
