import json, time, copy, urllib.request
import gibraltar as g
from node_server import load_priv
BASE = "http://127.0.0.1:8443"

def call(env):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "node.execute",
                       "params": {"envelope": env}}).encode()
    r = urllib.request.Request(BASE + "/rpc", body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]

def seq():
    return json.load(urllib.request.urlopen(BASE + "/health"))["last_seq"] + 1

def build(approver_roles=("omega",)):
    now = int(time.time())
    a = {"type": "read", "target": "eu1/state", "node": "eu1"}
    req = g.make_request(a, "spec", (), "s1", ttl=300, now=now - 5)
    ap = [g.sign(r, load_priv(r), req, now - 4) for r in approver_roles]
    return {"node_id": "eu1", "seq": seq(), "request": req, "approvals": ap}

# 1. nonce replay: same request, fresh seq
e = build(); print("first :", call(e)["detail"])
e["seq"] = seq(); print("replay:", call(e)["detail"])

# 2. tampered action after signing
e = build(); e["request"]["action"]["target"] = "eu1/other"
print("tamper:", call(e)["detail"])

# 3. extra approver (needs policy.key on this device)
try:
    e = build(("omega", "policy")); print("extra :", call(e)["detail"])
except FileNotFoundError as x:
    print("extra : skipped, no key:", x.filename)

# 4. stale seq
e = build(); e["seq"] = 0; print("stale :", call(e)["detail"])
