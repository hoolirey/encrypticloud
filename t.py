import json, time, urllib.request
import gibraltar as g
from node_server import load_priv

for k in ("REQUIRED", "BASE_TIER", "RED_FLAGS", "AMBER_FLAGS"):
    print(k, "=", getattr(g, k, "NOT FOUND"))

BASE = "http://127.0.0.1:8443"
h = json.load(urllib.request.urlopen(BASE + "/health"))
print("HEALTH:", h)

action = {"type": "read", "target": "eu1/state", "node": "eu1"}
tier = g.compute_tier(action, g.derive_flags(action, "s1", ()))
needed = g.REQUIRED[tier]
print("TIER:", tier, "NEEDED:", needed)
if tier != "GREEN":
    raise SystemExit("not GREEN, stopping (BASE_TIER likely lacks 'read')")

now = int(time.time())
req = g.make_request(action, "spec", (), "s1", ttl=300, now=now - 5)
approvals = [g.sign(r, load_priv(r), req, now - 4) for r in needed]
env = {"node_id": "eu1", "seq": h["last_seq"] + 1,
       "request": req, "approvals": approvals}
body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "node.execute",
                   "params": {"envelope": env}}).encode()
r = urllib.request.Request(BASE + "/rpc", body,
                           {"Content-Type": "application/json"})
print(json.dumps(json.load(urllib.request.urlopen(r)), indent=2))
