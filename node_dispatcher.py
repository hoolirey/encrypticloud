"""Local, passive SQLite queue for signed node-command envelopes."""
import hashlib
import json
import os
import sqlite3
import time
import uuid


class JobQueue:
    def __init__(self, db_path="data/jobs.sqlite3"):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), mode=0o700, exist_ok=True)
        os.chmod(os.path.dirname(self.db_path), 0o700)
        self._initialize()

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 10000")
        return db

    def _initialize(self):
        with self._connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.execute("PRAGMA synchronous = FULL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    envelope_hash TEXT NOT NULL UNIQUE,
                    envelope TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status = 'queued'),
                    created_at INTEGER NOT NULL
                )
            """)
        os.chmod(self.db_path, 0o600)

    def enqueue(self, envelope):
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be a JSON object")
        if not all(k in envelope for k in ("node_id", "seq", "request", "approvals")):
            raise ValueError("envelope is missing required fields")

        body = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        job_id = str(uuid.uuid4())

        with self._connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO jobs
                   (id, envelope_hash, envelope, status, created_at)
                   VALUES (?, ?, ?, 'queued', ?)""",
                (job_id, digest, body, int(time.time())),
            )
            row = db.execute(
                "SELECT id FROM jobs WHERE envelope_hash = ?", (digest,)
            ).fetchone()

        return row["id"]

    def get(self, job_id):
        with self._connect() as db:
            row = db.execute(
                "SELECT id, envelope, status, created_at FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "envelope": json.loads(row["envelope"]),
            "status": row["status"],
            "created_at": row["created_at"],
        }

    def list(self, limit=50):
        limit = max(1, min(int(limit), 200))
        with self._connect() as db:
            rows = db.execute(
                """SELECT id, status, created_at FROM jobs
                   ORDER BY created_at DESC, id LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
