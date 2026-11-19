import json, os, sys, time, urllib.error, urllib.request
import gibraltar as g
from node_agent import ALLOWLIST
from node_server import load_priv

PORT = next((a for a in sys.argv[1:] if a.isdigit()), "8444")
FULL, REPLAY = "--full" in sys.argv, "--replay" in sys.argv
BASE = f"http://127.0.0.1:{PORT}"
NODE_PUB = load_priv("eu1").public_key()
P = {r: load_priv(r) for r in ("omega", "policy", "owner", "owner_confirm")}
OWNER, CONFIRM = P["owner"], P["owner_confirm"]
fails = 0

def raw(body):
    r = urllib.request.Request(BASE + "/rpc", body, {"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(r))
    except urllib.error.HTTPError as e:
        return json.load(e)

def post(method, params):
    return raw(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())

def health(): return json.load(urllib.request.urlopen(BASE + "/health"))

def sig_ok(res):
    body = {k: v for k, v in res.items() if k != "sig"}
    try:
        NODE_PUB.verify(bytes.fromhex(res["sig"]), g.digest(body).encode())
        return True
    except Exception:
        return False

def check(name, got, want):
    global fails
    ok = got == want
    fails += not ok
    print("ok  " if ok else "FAIL", name, "" if ok else f"\n   want={want!r}\n   got ={got!r}")

def build(atype, spec, created_off=5, ttl=300, node="eu1", seq=None):
    now = int(time.time())
    req = g.make_request({"type": atype, "target": "eu1/svc", "node": node}, "spec", (), "s1",
                         ttl=ttl, now=now - created_off)
    ap = [g.sign(r, P[r], req, now - off) for r, off in spec]
    return {"node_id": "eu1", "seq": health()["last_seq"] + 1 if seq is None else seq,
            "request": req, "approvals": ap}

def run(env): return post("node.execute", {"envelope": env})["result"]

G = [("omega", 4)]
A = [("omega", 4), ("policy", 4), ("owner", 4)]

if REPLAY:  # after a restart: the captured request must still be refused
    env = json.load(open("captured_env.json"))
    env["seq"] = health()["last_seq"] + 1
    d = run(env)["detail"]
    check("replay after restart", d in ("DENY: nonce already used (replay)",
          "DENY: request expired or not yet valid"), True)
    print("detail:", d)
    sys.exit(1 if fails else 0)

print("HEALTH:", health())
check("omega key live", health().get("omega"), "ok")

e = build("read", G); r = run(e)
check("GREEN", (r["status"], r["detail"]), ("EXECUTED", "AUTHORIZED GREEN | state returned"))
check("result signature", sig_ok(r), True)
json.dump(e, open("captured_env.json", "w"))
check("replay", run(dict(e, seq=health()["last_seq"] + 1))["detail"], "DENY: nonce already used (replay)")
t = build("read", G); t["request"]["action"]["target"] = "x"
check("tamper", run(t)["detail"], "DENY: request integrity check failed")
check("extra approver", run(build("read", G + [("policy", 4)]))["detail"], "DENY: unexpected approvals: ['policy']")
check("stale seq", run(build("read", G, seq=health()["last_seq"]))["detail"], "stale sequence")
check("wrong node", run(build("read", G, node="eu2"))["detail"], "not addressed to this node")
check("ttl cap", run(build("read", G, ttl=7200))["detail"], "request ttl too long")
check("not in allowlist", run(build("route", G))["detail"], "action not in node allowlist")
check("AMBER missing", run(build("scale", G))["detail"], "DENY AMBER: missing policy, owner")
r = run(build("scale", A))
check("AMBER ok", (r["detail"], sig_ok(r)), ("AUTHORIZED AMBER | dry-run: scaled eu1/svc", True))
check("RED early", run(build("delete", [("omega", 100), ("policy", 100), ("owner", 100), ("owner_confirm", 90)],
      created_off=120, ttl=900))["detail"], "DENY RED: cooloff not satisfied")
r = run(build("delete", [("omega", 380), ("policy", 380), ("owner", 380), ("owner_confirm", 70)],
        created_off=400, ttl=900))
check("RED ok", (r["status"], r["detail"]), ("EXECUTED", "AUTHORIZED RED | dry-run: deleted eu1/svc"))
want = "AUTHORIZED GREEN | " + str(ALLOWLIST["health_check"](
    {"type": "health_check", "target": "eu1/svc", "node": "eu1"}))
check("health_check output", run(build("health_check", G))["detail"], want)
check("malformed envelope", run({})["detail"], "malformed command")
check("missing param", post("node.execute", {})["error"]["message"], "Missing required parameter: 'envelope'")
check("unknown method", post("nope", {})["error"]["message"], "Method not found: nope")
check("parse error", raw(b"{")["error"]["code"], -32700)

now = int(time.time())
def fsig(k, scope, ts): return k.sign(f"freeze|{scope}|{ts}".encode()).hex()
def usig(scope, ts): return OWNER.sign(f"unfreeze|{scope}|{ts}".encode()).hex()
def csig(scope, ts2): return CONFIRM.sign(f"unfreeze_confirm|{scope}|{ts2}".encode()).hex()
def freeze(k, scope, ts): return post("node.freeze", {"scope": scope, "ts": ts, "sig": fsig(k, scope, ts)})["result"]["detail"]
def unfreeze(u, u2, bad=False):
    s2 = OWNER.sign(b"x").hex() if bad else csig("eu1", u2)
    return post("node.unfreeze", {"scope": "eu1", "ts": u, "sig": usig("eu1", u), "ts2": u2, "sig2": s2})["result"]["detail"]
DENY_FZ = "DENY: wrong scope, stale, or replayed"
DENY_UF = "DENY: scope, cooling-off, or replay check failed"
check("freeze wrong key", freeze(P["policy"], "eu1", now), "DENY: freeze not signed by owner")
check("freeze wrong scope", freeze(OWNER, "eu2", now + 1), DENY_FZ)
check("freeze stale", freeze(OWNER, "eu1", now - 500), DENY_FZ)
check("unfreeze early", unfreeze(now - 5, now + 5), DENY_UF)
check("unfreeze bad confirm", unfreeze(now - 500, now - 100, bad=True), "DENY: unfreeze needs owner and owner_confirm")
check("unfreeze too old (new bound)", unfreeze(now - 3000, now - 2000), DENY_UF)

a = post("node.heartbeat", {"metrics": {"cpu": 1}})["result"]
b = post("node.heartbeat", {"metrics": {"cpu": 1}})["result"]
check("heartbeat", (sig_ok(a), sig_ok(b), b["seq"] == a["seq"] + 1), (True, True, True))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
en = post("node.enroll_request", {"region": "eu"})["result"]; cert = en["cert"]
try:
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert["pubkey"])).verify(
        bytes.fromhex(en["pop_sig"]), g.digest({"pop": cert["node_id"], "nonce": cert["nonce"]}).encode())
    pop = True
except Exception:
    pop = False
check("enroll", (pop, cert["pubkey"] == NODE_PUB.public_bytes_raw().hex()), (True, True))

if FULL:  # real freeze/unfreeze cycle, about 3 minutes
    F = int(time.time()) - 115
    check("freeze", freeze(OWNER, "eu1", F), "FROZEN: read-only")
    check("frozen AMBER", run(build("scale", A))["detail"], "node frozen: read-only")
    check("frozen READ", run(build("read", G))["detail"], "AUTHORIZED GREEN | state returned")
    u, u2 = F + 1, F + 301
    wait = u2 - time.time()
    if wait > 0:
        print(f"waiting {int(wait) + 1}s for the cooloff...", flush=True)
        time.sleep(wait + 1)
    check("unfreeze", unfreeze(u, u2), "UNFROZEN")
    check("READ after", run(build("read", G))["detail"], "AUTHORIZED GREEN | state returned")

if os.path.exists("cpp_state.json"):
    s = json.load(open("cpp_state.json"))
    print(f"state: {len(s['used'])} nonces, {len(s.get('used_exp', {}))} with expiry, last_seq {s['last_seq']}")
print("\nALL PASS" if not fails else f"\n{fails} FAILURE(S)")
sys.exit(1 if fails else 0)
