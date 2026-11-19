import os, tempfile, time
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import gibraltar as g
from trust_registry_new import TrustRegistry

K = Ed25519PrivateKey.generate
raw = lambda k: k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex()
now = int(time.time())
owner, o1, o2 = K(), K(), K()
path = os.path.join(tempfile.mkdtemp(), "trust_state.json")

def rec(k, issued): return {"pubkey": raw(k), "issued_at": issued, "expires_at": issued + 86400}
def reg(t, r):
    sig = owner.sign(f"register|{g.digest(r)}|{now}".encode()).hex()
    return t.register(r, sig, now, now)
def fresh(): return TrustRegistry(owner.public_key(), {}, path)  # simulates a restart

r1, r2 = rec(o1, now - 60), rec(o2, now - 30)
print("r1         :", reg(fresh(), r1))
print("replay r1  :", reg(fresh(), r1))
print("r2         :", reg(fresh(), r2))
print("replay r2  :", reg(fresh(), r2))
print("mode 600   :", oct(os.stat(path).st_mode & 0o777) == "0o600")
print("no tmp left:", not os.path.exists(path + ".tmp"))
