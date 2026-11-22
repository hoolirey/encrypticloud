"""Simulated TPM: node identity, key lifecycle, PCR measurements, attestation.

Key material never leaves the process by design. destroy() clears the
in-process reference; Python memory zeroization is best-effort and CPython
may retain copies in interpreter internals, so this is not a guarantee of
secure erasure akin to real hardware.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from svmc.exceptions import IdentityError

logger = logging.getLogger(__name__)

_PCR_INIT = "00" * 32


class VirtualTPM:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self._secret: bytes | None = None
        self.generation = 0
        self.pcrs: dict[int, str] = {}
        self._destroyed = False

    def _require_operational(self, action: str) -> bytes:
        if self._destroyed:
            raise IdentityError(f"cannot {action}: identity destroyed")
        if self._secret is None:
            raise IdentityError(f"cannot {action}: identity not provisioned")
        return self._secret

    def _extend(self, index: int, label: bytes) -> str:
        current = bytes.fromhex(self.pcrs.get(index, _PCR_INIT))
        self.pcrs[index] = hashlib.sha256(current + label).hexdigest()
        return self.pcrs[index]

    def provision(self) -> None:
        if self._destroyed:
            raise IdentityError("cannot provision: identity destroyed")
        if self._secret is not None:
            raise IdentityError("identity already provisioned")
        self._secret = secrets.token_bytes(32)
        self.generation = 1
        self.pcrs.clear()
        self._extend(0, b"svmc:provision")
        logger.info("tpm provisioned node_id=%s generation=1", self.node_id)

    def rotate(self) -> int:
        secret = self._require_operational("rotate")
        new_secret = bytearray(secret)
        new_secret[:] = secrets.token_bytes(32)
        self._secret = bytes(new_secret)
        self.generation += 1
        self._extend(1, b"svmc:rotate")
        logger.info("tpm rotated node_id=%s generation=%d", self.node_id, self.generation)
        return self.generation

    def measure(self, index: int, data: bytes) -> str:
        self._require_operational("measure")
        return self._extend(index, data)

    def attest(self, nonce: bytes) -> dict:
        secret = self._require_operational("attest")
        message = (
            nonce + self.node_id.encode("utf-8") + self.generation.to_bytes(8, "big")
        )
        signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return {
            "node_id": self.node_id,
            "generation": self.generation,
            "nonce": nonce.hex(),
            "signature": signature,
        }

    def verify_attestation(self, attestation: dict) -> bool:
        secret = self._require_operational("verify attestation")
        nonce = bytes.fromhex(attestation["nonce"])
        message = (
            nonce
            + self.node_id.encode("utf-8")
            + int(attestation["generation"]).to_bytes(8, "big")
        )
        expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, attestation["signature"])

    def destroy(self) -> None:
        if self._secret is not None:
            wipe = bytearray(self._secret)
            for i in range(len(wipe)):
                wipe[i] = 0
            self._secret = None
            del wipe
        self._destroyed = True
        logger.info("tpm destroyed node_id=%s generation=%d", self.node_id, self.generation)
