import time
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import gibraltar as g
from node_server import NodeAgent
from trust_registry_new import TrustRegistry

K = Ed25519PrivateKey.generate
raw = lambda k: k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex()
now = int(time.time())
owner, policy, oc, node, o1, o2, o3 = (K() for _ in range(7))
fixed = {"policy": policy.public_key(), "owner": owner.public_key(),
         "owner_confirm": oc.public_key()}

def mk(): return TrustRegistry(owner.public_key(), fixed)
def rec(k, issued, life=86400):
    return {"pubkey": raw(k), "issued_at": issued, "expires_at": issued + life}
def reg(t, r, ts=None):
    ts = now if ts is None else ts
    sig = owner.sign(f"register|{g.digest(r)}|{ts}".encode()).hex()
    return t.register(r, sig, ts, now)

trust = mk()
agent = NodeAgent("eu1", node, trust)
def attempt(k, label):
    t = int(time.time())
    req = g.make_request({"type": "read", "target": "eu1/state", "node": "eu1"},
                         "spec", (), "s1", ttl=300, now=t - 5)
    env = {"node_id": "eu1", "seq": agent.last_seq + 1, "request": req,
           "approvals": [g.sign("omega", k, req, t - 4)]}
    print(f"{label:26}", agent.handle_command(env, t)["detail"])

r1, r2 = rec(o1, now - 60), rec(o2, now - 30)
print("forged register :", trust.register(r2, "00" * 64, now, now))
print("register r1     :", reg(trust, r1)); attempt(o1, "omega1 registered")
print("register r2     :", reg(trust, r2))
attempt(o1, "omega1 after rotation"); attempt(o2, "omega2 after rotation")
print("replay r1       :", reg(trust, r1))
attempt(o1, "omega1 after replay"); attempt(o2, "omega2 after replay")
print("stale ts        :", reg(mk(), rec(o3, now - 10), ts=now - 1000))
print("future issued_at:", reg(mk(), rec(o3, now + 500)))
t2 = mk()
reg(t2, rec(o1, now - 100, 1100)); reg(t2, rec(o2, now - 50, 150))
print("omega at +50s   :", "omega" in t2.pubkeys_for(now + 50))
print("omega at +200s  :", "omega" in t2.pubkeys_for(now + 200))
