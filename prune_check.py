import json, time, urllib.request
import gibraltar as g
from node_server import load_priv
BASE = "http://127.0.0.1:8444"
def state(): return json.load(open("cpp_state.json"))
s = state()
print("before:", len(s["used"]), "nonces")
wait = max(s["used_exp"].values()) + 61 - time.time()
if wait > 0:
    print(f"waiting {int(wait)}s...", flush=True)
    time.sleep(wait)
now = int(time.time())
h = json.load(urllib.request.urlopen(BASE + "/health"))
req = g.make_request({"type": "read", "target": "eu1/state", "node": "eu1"}, "spec", (), "s1", ttl=300, now=now - 5)
env = {"node_id": "eu1", "seq": h["last_seq"] + 1, "request": req,
       "approvals": [g.sign("omega", load_priv("omega"), req, now - 4)]}
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "node.execute", "params": {"envelope": env}}).encode()
r = json.load(urllib.request.urlopen(urllib.request.Request(BASE + "/rpc", body, {"Content-Type": "application/json"})))
print(r["result"]["detail"])
s = state()
print("after :", len(s["used"]), "nonces (want 1)")
