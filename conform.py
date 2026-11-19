import json, subprocess, sys, time
import gibraltar as g
import node_agent as na
from node_server import load_priv, load_pub, KEY_DIR

authorize = getattr(g, "authorize", None) or na.authorize
ROLES = ("omega", "policy", "owner", "owner_confirm")
PUBS = {r: load_pub(r) for r in ROLES}
PRIV = {r: load_priv(r) for r in ROLES}
BIN = "cpp/conform"

def cpp(mode, payload, *args):
    p = subprocess.run([BIN, mode, *args], input=json.dumps(payload).encode(), capture_output=True)
    if p.returncode:
        return f"EXIT {p.returncode}: {p.stderr.decode().strip()}"
    return p.stdout.decode().rstrip("\n")

fails = 0
def report(name, got, want):
    global fails
    ok = got == want
    fails += not ok
    print("ok  " if ok else "FAIL", name, "" if ok else f"\n   py ={want!r}\n   cpp={got!r}")

# canonical JSON / digest vectors
VEC = [{}, [], {"b": 1, "a": [1, 2, {"z": None, "y": True}]},
       {"s": "é\u2028\u007f\x00\x1f\"\\/\n\t\U0001F600"}, {"n": 9007199254740993, "m": -5},
       {"ключ": "значение", "a": "b"}, {"": ""}, [[[[]]]], {"f": False}]
for i, v in enumerate(VEC):
    report(f"digest[{i}]", cpp("digest", v), g.digest(v))

def case(atype, spec, created_off=5, ttl=300, params=None, snap="s1", flags=(),
         tamper=None, signer=None):
    now = int(time.time())
    action = {"type": atype, "target": "eu1/svc", "node": "eu1"}
    if params is not None:
        action["params"] = params
    req = g.make_request(action, "spec", flags, snap, ttl=ttl, now=now - created_off)
    ap = [g.sign(r, (signer or {}).get(r, PRIV[r]), req, now - off) for r, off in spec]
    if tamper:
        tamper(req, ap)
    return {"now": now, "req": req, "approvals": ap}

G = [("omega", 4)]
A = [("omega", 4), ("policy", 4), ("owner", 4)]
RED_OK = dict(spec=[("omega", 380), ("policy", 380), ("owner", 380), ("owner_confirm", 70)],
              created_off=400, ttl=900)
RED_EARLY = dict(spec=[("omega", 100), ("policy", 100), ("owner", 100), ("owner_confirm", 90)],
                 created_off=120, ttl=900)
CASES = [
    ("GREEN ok", case("read", G)),
    ("AMBER ok", case("scale", A)),
    ("AMBER missing", case("scale", G)),
    ("AMBER extra", case("scale", A + [("owner_confirm", 4)])),
    ("RED ok", case("delete", **RED_OK)),
    ("RED early", case("delete", **RED_EARLY)),
    ("RED no snapshot", case("delete", snap="", **RED_OK)),
    ("duplicate omega", case("read", G + G)),
    ("wrong key", case("read", G, signer={"omega": PRIV["policy"]})),
    ("expired", case("read", [("omega", 4)], created_off=400, ttl=300)),
    ("approval before created", case("read", [("omega", 20)])),
    ("approval in future", case("read", [("omega", -10)])),
    ("tamper action", case("read", G, tamper=lambda r, a: r["action"].update(target="x"))),
    ("tamper nonce", case("read", G, tamper=lambda r, a: r.update(nonce="0" * 32))),
    ("delete plan_hash", case("read", G, tamper=lambda r, a: r.pop("plan_hash"))),
    ("garbage sig", case("read", G, tamper=lambda r, a: a[0].update(sig="zz"))),
    ("short sig", case("read", G, tamper=lambda r, a: a[0].update(sig="00" * 10))),
    ("missing sig", case("read", G, tamper=lambda r, a: a[0].pop("sig"))),
    ("expose -> AMBER", case("read", G, params={"expose": True})),
    ("grant -> RED", case("read", G, params={"grant": True})),
    ("ANOMALY flag", case("read", G, flags=("ANOMALY",))),
    ("two flags", case("read", G, flags=("A", "B"))),
    ("unknown type", case("frobnicate", G)),
]
for name, c in CASES:
    want = authorize(c["req"], c["approvals"], PUBS, set(), c["now"])
    report(name, cpp("auth", c, KEY_DIR), f"{int(want[0])}\t{want[1]}")

print("\nALL MATCH" if not fails else f"\n{fails} MISMATCH(ES)")
sys.exit(1 if fails else 0)
