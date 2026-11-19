import json, time, urllib.request
import gibraltar as g
from node_server import load_priv
BASE = "http://127.0.0.1:8443"
NODE_PUB = load_priv("eu1").public_key()

def call(env):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "node.execute",
                       "params": {"envelope": env}}).encode()
    r = urllib.request.Request(BASE + "/rpc", body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]

def seq():
    return json.load(urllib.request.urlopen(BASE + "/health"))["last_seq"] + 1

def check_sig(res):
    body = {k: v for k, v in res.items() if k != "sig"}
    try:
        NODE_PUB.verify(bytes.fromhex(res["sig"]), g.digest(body).encode())
        return True
    except Exception:
        return False

def run(atype, ts_by_role, created_off=5):
    now = int(time.time())
    a = {"type": atype, "target": "eu1/svc", "node": "eu1", "params": {}}
    req = g.make_request(a, "spec", (), "s1", ttl=900, now=now - created_off)
    ap = [g.sign(r, load_priv(r), req, now - off) for r, off in ts_by_role]
    return call({"node_id": "eu1", "seq": seq(), "request": req, "approvals": ap})

# 1. positive AMBER
r = run("scale", [("omega", 4), ("policy", 4), ("owner", 4)])
print("AMBER :", r["status"], "|", r["detail"], "| sig ok:", check_sig(r))

# 2. tampered result must fail verification
t = dict(r, detail="tampered"); print("tamper sig ok (want False):", check_sig(t))

# 3. RED, cooloff NOT met (owner_confirm only 10s after owner)
r = run("delete", [("omega", 100), ("policy", 100), ("owner", 100), ("owner_confirm", 90)], 120)
print("RED early:", r["status"], "|", r["detail"])

# 4. RED, cooloff met (owner_confirm 310s after owner), dry-run handler only
r = run("delete", [("omega", 380), ("policy", 380), ("owner", 380), ("owner_confirm", 70)], 400)
print("RED ok   :", r["status"], "|", r["detail"], "| sig ok:", check_sig(r))

print("HEALTH:", json.load(urllib.request.urlopen(BASE + "/health")))
