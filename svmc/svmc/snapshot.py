"""Snapshot/restore: state files for saving and resetting test nodes."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from svmc.exceptions import SnapshotError


class SnapshotManager:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, state: dict[str, Any], snapshot_id: str | None = None) -> str:
        snapshot_id = snapshot_id or ("snap-" + secrets.token_hex(8))
        path = self.root / f"{snapshot_id}.json"
        path.write_text(json.dumps(state, sort_keys=True, indent=2), encoding="utf-8")
        return snapshot_id

    def load(self, snapshot_id: str) -> dict[str, Any]:
        path = self.root / f"{snapshot_id}.json"
        if not path.is_file():
            raise SnapshotError(f"unknown snapshot {snapshot_id!r}")
        return json.loads(path.read_text(encoding="utf-8"))

    def list_snapshots(self) -> list[str]:
        return sorted(p.stem for p in self.root.glob("*.json"))
