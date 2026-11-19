import json, os, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from gibraltar import digest

REG_WINDOW = 120  # max |now - ts| for a registration signature
SKEW = 60         # max seconds a record's issued_at may be in the future


class TrustRegistry:
    def __init__(self, owner_pub, fixed, state_path=None):
        self.owner_pub, self.fixed, self.records = owner_pub, dict(fixed), []
        self.state_path, self.max_issued = state_path, 0
        if state_path and os.path.exists(state_path):
            with open(state_path) as f:  # corrupt file raises: fail loudly
                self.max_issued = int(json.load(f)["max_issued"])

    def _save(self):
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"max_issued": self.max_issued}, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_path)

    def register(self, rec, owner_sig, ts, now=None):
        now = int(time.time()) if now is None else int(now)
        try:
            self.owner_pub.verify(bytes.fromhex(owner_sig),
                                  f"register|{digest(rec)}|{ts}".encode())
        except (InvalidSignature, ValueError, TypeError):
            return False, "DENY: record not signed by owner"
        try:
            if abs(now - int(ts)) > REG_WINDOW:
                return False, "DENY: registration stale"
            issued, expires = int(rec["issued_at"]), int(rec["expires_at"])
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(rec["pubkey"]))
        except (KeyError, TypeError, ValueError):
            return False, "DENY: malformed record"
        if not issued < expires or issued > now + SKEW:
            return False, "DENY: bad validity window"
        if issued <= self.max_issued:
            return False, "DENY: not newer than current record (replay)"
        self.max_issued = issued
        self._save()
        self.records.append(rec)
        return True, "REGISTERED"

    def pubkeys_for(self, now):
        keys = dict(self.fixed)
        seen = [r for r in self.records if r["issued_at"] <= now]
        if seen:
            latest = max(seen, key=lambda r: r["issued_at"])
            if now < latest["expires_at"]:
                keys["omega"] = Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(latest["pubkey"]))
        return keys
