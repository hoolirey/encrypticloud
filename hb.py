import json, urllib.request
import gibraltar as g
from node_server import load_priv, Ed25519PublicKey
BASE = "http://127.0.0.1:8443"
NODE_PUB = load_priv("eu1").public_key()

def rpc(method, params):
    b = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    r = urllib.request.Request(BASE + "/rpc", b, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]

def ok(pub, sig, body):
    try: pub.verify(bytes.fromhex(sig), g.digest(body).encode()); return True
    except Exception: return False

a = rpc("node.heartbeat", {"metrics": {"cpu": 1}})
b = rpc("node.heartbeat", {"metrics": {"cpu": 1}})
for h in (a, b):
    print("hb seq", h["seq"], "sig ok:", ok(NODE_PUB, h["sig"], {k: v for k, v in h.items() if k != "sig"}))
print("seq increases:", b["seq"] == a["seq"] + 1)

e = rpc("node.enroll_request", {"region": "eu"})
cert = e["cert"]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert["pubkey"]))
print("PoP ok:", ok(pub, e["pop_sig"], {"pop": cert["node_id"], "nonce": cert["nonce"]}))
print("cert key == eu1 key:", cert["pubkey"] == NODE_PUB.public_bytes_raw().hex())
