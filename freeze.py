import json, time, urllib.request
import gibraltar as g
from node_server import load_priv
from node_agent import COOLOFF
BASE = "http://127.0.0.1:8443"
OWNER, CONFIRM = load_priv("owner"), load_priv("owner_confirm")

def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    r = urllib.request.Request(BASE + "/rpc", body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]

def health(): return json.load(urllib.request.urlopen(BASE + "/health"))

def exec_(atype, roles):
    now = int(time.time())
    a = {"type": atype, "target": "eu1/svc", "node": "eu1", "params": {}}
    req = g.make_request(a, "spec", (), "s1", ttl=300, now=now - 5)
    ap = [g.sign(r, load_priv(r), req, now - 4) for r in roles]
    env = {"node_id": "eu1", "seq": health()["last_seq"] + 1, "request": req, "approvals": ap}
    return rpc("node.execute", {"envelope": env})

def fsig(scope, ts): return OWNER.sign(f"freeze|{scope}|{ts}".encode()).hex()
def usig(scope, ts): return OWNER.sign(f"unfreeze|{scope}|{ts}".encode()).hex()
def csig(scope, ts2): return CONFIRM.sign(f"unfreeze_confirm|{scope}|{ts2}".encode()).hex()

ts = int(time.time())
print("freeze        :", rpc("node.freeze", {"scope": "eu1", "ts": ts, "sig": fsig("eu1", ts)}))
print("freeze replay :", rpc("node.freeze", {"scope": "eu1", "ts": ts, "sig": fsig("eu1", ts)})["detail"])
ts_w = ts + 1
print("wrong scope   :", rpc("node.freeze", {"scope": "eu2", "ts": ts_w, "sig": fsig("eu2", ts_w)})["detail"])
print("frozen READ   :", exec_("read", ["omega"])["detail"])
print("frozen AMBER  :", exec_("scale", ["omega", "policy", "owner"])["detail"])

u = ts + 1
early = u + 10
print("early unfreeze:", rpc("node.unfreeze", {"scope": "eu1", "ts": u, "sig": usig("eu1", u),
      "ts2": early, "sig2": csig("eu1", early)})["detail"])

u2 = u + COOLOFF
wait = u2 - time.time()
if wait > 0:
    print(f"waiting {int(wait)+1}s for real cooloff...", flush=True)
    time.sleep(wait + 1)
print("unfreeze      :", rpc("node.unfreeze", {"scope": "eu1", "ts": u, "sig": usig("eu1", u),
      "ts2": u2, "sig2": csig("eu1", u2)}))
print("HEALTH        :", health())
print("READ after    :", exec_("read", ["omega"])["detail"])
