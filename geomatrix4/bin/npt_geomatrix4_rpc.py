#!/usr/bin/env python3
"""Geomatrix4 RPC daemon.

Auth (deny-by-default): every request must carry
  X-NPT-Key-Id, X-NPT-Timestamp, X-NPT-Counter, X-NPT-Signature
where Signature = HMAC-SHA3-256(key, "METHOD|PATH|timestamp|counter") in hex.
Checks, in order: headers present, signer known, timestamp within skew,
signature valid, counter strictly greater than the signer's last accepted one.
Auth is required unless bound to loopback; set NPT_REQUIRE_AUTH=1 to force it there too.
Every request (accepted or rejected) is appended to a SHA3-384 hash-chained audit log.
"""
import errno, hashlib, hmac, http.server, ipaddress, json, os, socket, sys, threading, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONF = os.path.join(ROOT, "etc", "abs256_4", "node_topology.conf")
KEY_DIR = os.path.join(ROOT, "etc", "abs256_4", "keys")
COUNTERS = os.path.join(ROOT, "var", "hyperplane_w4", "counters.json")
AUDIT = os.path.join(ROOT, "var", "log", "rpc", "audit.log")

BIND = os.environ.get("NPT_BIND", "::1")        # loopback by default; NPT_BIND=:: exposes it
PORT = int(os.environ.get("NPT_PORT", "8443"))
SKEW = int(os.environ.get("NPT_SKEW_S", "30"))
GENESIS = hashlib.sha3_384(b"NPT-GEOMATRIX4-AUDIT-GENESIS").hexdigest()

LOCK = threading.Lock()
KEYS = {}
STATE = {"counters": {}, "head": GENESIS}

def load_conf(path):
    cfg = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k] = v.strip('"')
    return cfg

def load_state():
    for fn in sorted(os.listdir(KEY_DIR)) if os.path.isdir(KEY_DIR) else []:
        if fn.endswith(".key"):
            with open(os.path.join(KEY_DIR, fn)) as f:
                KEYS[fn[:-4]] = bytes.fromhex(f.read().strip())
    if os.path.exists(COUNTERS):
        with open(COUNTERS) as f:
            STATE["counters"] = json.load(f)
    if os.path.exists(AUDIT):
        last = None
        with open(AUDIT) as f:
            for last in f:
                pass
        if last:
            STATE["head"] = hashlib.sha3_384(last.encode()).hexdigest()

def save_counters():
    tmp = COUNTERS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(STATE["counters"], f)
    os.replace(tmp, COUNTERS)

def audit(entry):
    """Append-only, hash-chained: each line embeds the digest of the previous line."""
    entry["prev"] = STATE["head"]
    line = json.dumps(entry, sort_keys=True) + "\n"
    with open(AUDIT, "a") as f:
        f.write(line)
    STATE["head"] = hashlib.sha3_384(line.encode()).hexdigest()

def derive_ipv6(x, y, z, w, tick):
    payload = f"NPT4|X={x:.3f}|Y={y:.3f}|Z={z:.3f}|W={w:.3f}|TICK={tick}"
    d = hashlib.sha3_256(payload.encode()).hexdigest()
    groups = ["fd4e"] + [d[i:i + 4] for i in range(0, 28, 4)]
    return str(ipaddress.IPv6Address(":".join(groups)))

def is_loopback(addr):
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False

AUTH_REQUIRED = os.environ.get("NPT_REQUIRE_AUTH") == "1" or not is_loopback(BIND)

class Handler(http.server.BaseHTTPRequestHandler):
    def authenticate(self):
        h = self.headers
        kid, ts, ctr, sig = (h.get(n) for n in
            ("X-NPT-Key-Id", "X-NPT-Timestamp", "X-NPT-Counter", "X-NPT-Signature"))
        if not (kid and ts and ctr and sig):
            return None, "missing_headers"
        key = KEYS.get(kid)
        if key is None:
            return None, "unknown_signer"
        try:
            ts_i, ctr_i = int(ts), int(ctr)
        except ValueError:
            return kid, "malformed"
        if abs(time.time() - ts_i) > SKEW:
            return kid, "stale_timestamp"
        msg = f"{self.command}|{self.path}|{ts_i}|{ctr_i}".encode()
        expect = hmac.new(key, msg, hashlib.sha3_256).hexdigest()
        if not hmac.compare_digest(expect, sig.lower()):
            return kid, "bad_signature"
        with LOCK:                                   # counter moves only after the signature verified
            if ctr_i <= STATE["counters"].get(kid, -1):
                return kid, "replay"
            STATE["counters"][kid] = ctr_i
            save_counters()
        return kid, "ok"

    def reply(self, code, obj):
        body = json.dumps(obj, indent=2).encode() + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        signer, result = ("-", "open_loopback")
        if AUTH_REQUIRED or self.headers.get("X-NPT-Signature"):
            signer, result = self.authenticate()
        with LOCK:
            audit({"ts": int(time.time()), "method": self.command, "path": self.path,
                   "client": self.client_address[0], "signer": signer, "result": result})
        if result not in ("ok", "open_loopback"):
            return self.reply(401, {"error": "unauthorized"})   # reason stays in the audit log only
        cfg = load_conf(CONF)
        x = float(cfg["GEOSPATIAL_X_M"]); y = float(cfg["GEOSPATIAL_Y_M"])
        z = float(cfg["GEOSPATIAL_Z_DEPTH_M"]); w = float(cfg["HYPERPLANE_W4_M"])
        lhs, rhs = (x * y * z) ** 3, w ** 4
        tick = int(time.time())
        self.reply(200, {
            "node": cfg["NODE_DESIGNATION"],
            "equation": "(x*y*z)^3 = w^4",
            "lhs": lhs, "rhs": rhs, "balanced": abs(lhs - rhs) < 1e-9,
            "metatick": tick,
            "derived_ipv6": derive_ipv6(x, y, z, w, tick),
        })

    def log_message(self, *a):
        pass

class Server6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

def make_server():
    try:
        ipv4 = isinstance(ipaddress.ip_address(BIND), ipaddress.IPv4Address)
    except ValueError:
        ipv4 = False
    if ipv4:
        return http.server.ThreadingHTTPServer((BIND, PORT), Handler), BIND
    try:
        return Server6((BIND, PORT), Handler), BIND
    except OSError as e:
        if e.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            raise                                # e.g. port in use: fail loudly
        return http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler), "127.0.0.1"

if __name__ == "__main__":
    load_state()
    srv, bound = make_server()
    mode = "signed requests required" if AUTH_REQUIRED else "open on loopback"
    print(f"[NPT-RPC] listening on [{bound}]:{PORT} ({mode})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
