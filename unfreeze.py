import json, os, time, urllib.request
from node_server import load_priv, BASE_DIR
from node_agent import COOLOFF
BASE = "http://127.0.0.1:8443"
OWNER, CONFIRM = load_priv("owner"), load_priv("owner_confirm")

def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    r = urllib.request.Request(BASE + "/rpc", body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]

with open(os.path.join(BASE_DIR, "eu1_state.json")) as f:
    last_ctl = json.load(f)["last_ctl"]
u = last_ctl + 1
u2 = u + COOLOFF
wait = u2 - time.time()
if wait > 0:
    print(f"waiting {int(wait)+1}s...", flush=True)
    time.sleep(wait + 1)
print(rpc("node.unfreeze", {
    "scope": "eu1",
    "ts": u,  "sig":  OWNER.sign(f"unfreeze|eu1|{u}".encode()).hex(),
    "ts2": u2, "sig2": CONFIRM.sign(f"unfreeze_confirm|eu1|{u2}".encode()).hex()}))
print(json.load(urllib.request.urlopen(BASE + "/health")))
