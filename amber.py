import json, time, urllib.request
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

def build(roles):
    now = int(time.time())
    a = {"type": "scale", "target": "eu1/svc", "node": "eu1", "params": {}}
    req = g.make_request(a, "spec", (), "s1", ttl=300, now=now - 5)
    ap = [g.sign(r, load_priv(r), req, now - 4) for r in roles]
    return {"node_id": "eu1", "seq": seq(), "request": req, "approvals": ap}

print("omega only      :", call(build(("omega",)))["detail"])
print("omega+policy    :", call(build(("omega", "policy")))["detail"])
print("with confirm    :", call(build(("omega", "policy", "owner", "owner_confirm")))["detail"])
