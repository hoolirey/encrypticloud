"""STAND-IN omega_register, inferred from node_agent.py call sites. In-memory only."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from gibraltar import digest


def pub_hex(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def owner_sign(key, msg):
    return key.sign(msg.encode()).hex()


def make_record(omega_pub, ts, lifetime=90 * 86400):
    return {"role": "omega", "pubkey": pub_hex(omega_pub), "issued_at": ts, "expires_at": ts + lifetime}


class TrustRegistry:
    def __init__(self, owner_pub, fixed):
        self.owner_pub, self.fixed, self.records = owner_pub, dict(fixed), []

    def register(self, rec, owner_sig, ts):
        try:
            self.owner_pub.verify(bytes.fromhex(owner_sig), f"register|{digest(rec)}|{ts}".encode())
        except (InvalidSignature, ValueError):
            return False, "DENY: record not signed by owner"
        self.records.append(rec)
        return True, "REGISTERED"

    def pubkeys_for(self, now):
        keys = dict(self.fixed)
        live = [r for r in self.records if r["issued_at"] <= now < r["expires_at"]]
        if live:
            keys["omega"] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(live[-1]["pubkey"]))
        return keys
