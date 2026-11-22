"""Append-only, hash-chained audit record backed by SQLite.

There is no update or delete code path; tampering is detected by
:meth:`AuditRecorder.verify_chain`.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
from typing import Any, Callable

from svmc.clock import utcnow
from svmc.exceptions import ChainIntegrityError

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    node_id TEXT,
    details TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
)
"""


class AuditRecorder:
    def __init__(self, db_path: str, now_fn: Callable[[], datetime.datetime] | None = None):
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        self._now_fn = now_fn or utcnow

    def record(
        self,
        action: str,
        actor: str,
        node_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> int:
        ts = self._now_fn().isoformat()
        details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        prev_hash = self._last_hash()
        digest = self._digest(prev_hash, ts, actor, action, node_id or "", details_json)
        cursor = self._conn.execute(
            "INSERT INTO audit_events (ts, actor, action, node_id, details, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, actor, action, node_id, details_json, prev_hash, digest),
        )
        self._conn.commit()
        return int(cursor.lastrowid)

    @staticmethod
    def _digest(
        prev_hash: str, ts: str, actor: str, action: str, node_id: str, details_json: str
    ) -> str:
        payload = "\x00".join((prev_hash, ts, actor, action, node_id, details_json))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH

    def events(
        self, node_id: str | None = None, action: str | None = None
    ) -> list[dict[str, Any]]:
        query = (
            "SELECT seq, ts, actor, action, node_id, details FROM audit_events WHERE 1=1"
        )
        params: list[Any] = []
        if node_id is not None:
            query += " AND node_id = ?"
            params.append(node_id)
        if action is not None:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY seq ASC"
        rows = self._conn.execute(query, params).fetchall()
        output = []
        for seq, ts, actor, action_value, event_node_id, details_json in rows:
            output.append(
                {
                    "seq": seq,
                    "ts": ts,
                    "actor": actor,
                    "action": action_value,
                    "node_id": event_node_id,
                    "details": json.loads(details_json),
                }
            )
        return output

    def verify_chain(self) -> bool:
        prev_hash = GENESIS_HASH
        for seq, ts, actor, action, node_id, details_json, stored_prev, stored_hash in (
            self._conn.execute(
                "SELECT seq, ts, actor, action, node_id, details, prev_hash, hash "
                "FROM audit_events ORDER BY seq ASC"
            ).fetchall()
        ):
            if stored_prev != prev_hash:
                raise ChainIntegrityError(f"broken chain at seq {seq}")
            expected = self._digest(prev_hash, ts, actor, action, node_id or "", details_json)
            if stored_hash != expected:
                raise ChainIntegrityError(f"hash mismatch at seq {seq}")
            prev_hash = stored_hash
        return True

    def close(self) -> None:
        self._conn.close()
