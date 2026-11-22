"""Simulated encrypted disk: files at rest are always ciphertext on disk.

Encryption is Fernet (AES-128-CBC + HMAC-SHA256) via the mandatory
``cryptography`` dependency.
"""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from svmc.exceptions import CapacityExceededError, NodeStateError


class VirtualEncryptedDisk:
    HEADER = b"SVMCENC1"

    def __init__(self, root: Path | str, key: bytes, max_bytes: int):
        if len(key) < 32:
            raise ValueError("key must be at least 32 bytes")
        self._key = bytes(key)
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self._fernet = Fernet(base64.urlsafe_b64encode(self._key))

    @property
    def used_bytes(self) -> int:
        if not self.root.is_dir():
            raise NodeStateError("storage was destroyed")
        return sum(p.stat().st_size for p in self.root.iterdir() if p.is_file())

    def _encrypt(self, data: bytes) -> bytes:
        return self.HEADER + self._fernet.encrypt(data)

    def _decrypt(self, blob: bytes) -> bytes:
        if not blob.startswith(self.HEADER):
            raise ValueError("blob is not an svmc encrypted container")
        try:
            return self._fernet.decrypt(blob[len(self.HEADER) :])
        except InvalidToken as exc:
            raise ValueError("decryption failed: wrong key or corrupt blob") from exc

    def _resolve(self, name: str | Path) -> Path:
        if isinstance(name, Path):
            return name
        if not name or "/" in name or "\\" in name or Path(name).name != name:
            raise ValueError(f"invalid file name {name!r}")
        return self.root / name

    def write_file(self, name: str, data: bytes | str) -> Path:
        payload = data.encode("utf-8") if isinstance(data, str) else data
        blob = self._encrypt(payload)
        if self.used_bytes + len(blob) > self.max_bytes:
            raise CapacityExceededError(
                f"disk limit: used={self.used_bytes} requested={len(blob)} max={self.max_bytes}"
            )
        path = self._resolve(name)
        path.write_bytes(blob)
        return path

    def read_file(self, name: str | Path) -> bytes:
        path = self._resolve(name)
        if not path.is_file():
            raise FileNotFoundError(name)
        return self._decrypt(path.read_bytes())

    def list_files(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_file())

    def secure_delete(self, name: str | Path) -> None:
        """Overwrite then unlink. Best-effort only: not guaranteed against
        copy-on-write or journaling filesystems, OS page caches, or backups."""
        path = self._resolve(name)
        if not path.is_file():
            raise FileNotFoundError(name)
        size = path.stat().st_size
        with open(path, "wb") as fh:
            fh.write(secrets.token_bytes(max(size, 1)))
        path.write_bytes(secrets.token_bytes(max(size, 1)))
        path.unlink()

    def wipe(self) -> None:
        for name in self.list_files():
            self.secure_delete(name)
