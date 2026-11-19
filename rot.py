import time
from cryptography.hazmat.primitives import serialization as S
import gibraltar as g
from node_server import NodeAgent, TrustRegistry, Ed25519PrivateKey

K = Ed25519PrivateKey.generate
raw = lambda k: k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
now = int(time.time())
owner, policy, oc, node, o1, o2 = (K() for _ in range(6))
fixed = {"policy": policy.public_key(), "owner": owner.public_key(),
         "owner_confirm": oc.public_key()}
trust = TrustRegistry(owner.public_key(), fixed)
agent = NodeAgent("eu1", node, trust)

def rec(k, issued): return {"pubkey": raw(k).hex(), "issued_at": issued, "expires_at": issued + 86400}
def reg(r):
    sig = owner.sign(f"register|{g.digest(r)}|{now}".encode()).hex()
    return trust.register(r, sig, now)
def attempt(k, label):
    t = int(time.time())
    req = g.make_request({"type": "read", "target": "eu1/state", "node": "eu1"},
                         "spec", (), "s1", ttl=300, now=t - 5)
    env = {"node_id": "eu1", "seq": agent.last_seq + 1, "request": req,
           "approvals": [g.sign("omega", k, req, t - 4)]}
    print(f"{label:26}", agent.handle_command(env, t)["detail"])

r1, r2 = rec(o1, now - 60), rec(o2, now - 30)
print("forged register:", trust.register(r2, "00" * 64, now))
reg(r1); attempt(o1, "omega1 registered")
attempt(o2, "omega2 not registered")
reg(r2); attempt(o1, "omega1 after rotation")
attempt(o2, "omega2 after rotation")
reg(r1); attempt(o1, "omega1 re-registered")
attempt(o2, "omega2 after re-register")
