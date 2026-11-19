"""Node agent protocols for the Encrypticloud domain (reference implementation, dry-run).

Zero trust: the node re-verifies every command itself with Gibraltar's authorize().
It never trusts the controller, the reconciler, or the network path.
Protocols: enroll, heartbeat, command/result, freeze/unfreeze.
"""
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from gibraltar import digest, authorize, derive_flags, compute_tier, COOLOFF
from omega_register import pub_hex

ALLOWLIST = {  # the only actions this node can ever execute (dry-run handlers)
    "read": lambda a: "state returned",
    "health_check": lambda a: "healthy",
    "place": lambda a: f"dry-run: placed {a['target']}",
    "scale": lambda a: f"dry-run: scaled {a['target']}",
    "workload_create": lambda a: f"dry-run: created {a['target']}",
    "config_edit": lambda a: f"dry-run: edited {a['target']}",
    "delete": lambda a: f"dry-run: deleted {a['target']}",
}


def msign(key, body):
    return key.sign(digest(body).encode()).hex()


def mverify(pub, body, sig):
    try:
        pub.verify(bytes.fromhex(sig), digest(body).encode())
        return True
    except (InvalidSignature, ValueError):
        return False


class NodeRegistry:
    """Controller-side list of enrolled nodes. Enrolling a node is a RED action: owner signs."""

    def __init__(self, owner_pub):
        self.owner_pub, self.nodes = owner_pub, {}

    def enroll(self, cert, pop_sig, owner_sig, ts):
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert["pubkey"]))
        if not mverify(pub, {"pop": cert["node_id"], "nonce": cert["nonce"]}, pop_sig):
            return False, "DENY: no proof of key possession"
        if cert["expires_at"] <= ts or cert["issued_at"] > ts:
            return False, "DENY: certificate expired or not yet valid"
        try:
            self.owner_pub.verify(bytes.fromhex(owner_sig), f"enroll|{digest(cert)}|{ts}".encode())
        except (InvalidSignature, ValueError):
            return False, "DENY: enrollment not signed by owner"
        old = self.nodes.get(cert["node_id"])
        if old and old["pubkey"] != cert["pubkey"]:
            return False, "DENY: node id already enrolled with another key (revoke first)"
        self.nodes[cert["node_id"]] = cert
        return True, f"ENROLLED {cert['node_id']} ({cert['region']})"

    def verify_heartbeat(self, hb, last_seq=-1, now=None):
        cert = self.nodes.get(hb["node_id"])
        if not cert:
            return False, "DENY: unknown node"
        if now is not None and now >= cert["expires_at"]:
            return False, "DENY: certificate expired"
        body = {k: v for k, v in hb.items() if k != "sig"}
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert["pubkey"]))
        if not mverify(pub, body, hb["sig"]):
            return False, "DENY: bad heartbeat signature"
        if hb["seq"] <= last_seq:
            return False, "DENY: stale or replayed heartbeat"
        return True, "OK"


class NodeAgent:
    def __init__(self, node_id, key, trust, state_path=None):
        self.node_id, self.key, self.trust, self.state_path = node_id, key, trust, state_path
        self.used, self.last_seq, self.hb_seq, self.frozen, self.last_ctl = set(), -1, 0, False, 0
        if state_path and os.path.exists(state_path):
            with open(state_path) as f:
                s = json.load(f)
            self.used = set(s["used"])
            self.last_seq, self.frozen, self.last_ctl = s["last_seq"], s["frozen"], s["last_ctl"]
            self.hb_seq = s.get("hb_seq", 0)

    def _save(self):
        """Atomic write so a crash or Android kill can't corrupt replay state."""
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        data = {"used": sorted(self.used), "last_seq": self.last_seq, "frozen": self.frozen,
                "last_ctl": self.last_ctl, "hb_seq": self.hb_seq}
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_path)

    def enroll_request(self, region, now):
        cert = {"node_id": self.node_id, "pubkey": pub_hex(self.key.public_key()), "region": region,
                "issued_at": now, "expires_at": now + 90 * 86400, "nonce": os.urandom(8).hex()}
        return cert, msign(self.key, {"pop": self.node_id, "nonce": cert["nonce"]})

    def heartbeat(self, metrics, now):
        self.hb_seq += 1
        self._save()
        body = {"type": "heartbeat", "node_id": self.node_id, "seq": self.hb_seq, "ts": now,
                "frozen": self.frozen, "metrics": metrics}
        return dict(body, sig=msign(self.key, body))

    def _result(self, env, status, detail, now):
        body = {"type": "result", "node_id": self.node_id, "seq": env.get("seq"), "ts": now,
                "plan_hash": env.get("request", {}).get("plan_hash"), "status": status, "detail": detail}
        return dict(body, sig=msign(self.key, body))

    def handle_command(self, env, now):
        try:
            req, approvals = env["request"], env["approvals"]
            if env["node_id"] != self.node_id or req["action"].get("node") != self.node_id:
                return self._result(env, "DENIED", "not addressed to this node", now)
            if env["seq"] <= self.last_seq:
                return self._result(env, "DENIED", "stale sequence", now)
            tier = compute_tier(req["action"], derive_flags(req["action"], req["snapshot_id"], req["omega_flags"]))
            if self.frozen and tier != "GREEN":
                return self._result(env, "DENIED", "node frozen: read-only", now)
            ok, why = authorize(req, approvals, self.trust.pubkeys_for(now), self.used, now)
            self._save()  # authorize() burns the nonce even on denial; persist it
            if not ok:
                return self._result(env, "DENIED", why, now)
            handler = ALLOWLIST.get(req["action"]["type"])
            if not handler:
                return self._result(env, "DENIED", "action not in node allowlist", now)
            out = handler(req["action"])
            self.last_seq = env["seq"]
            self._save()
            return self._result(env, "EXECUTED", f"{why} | {out}", now)
        except (KeyError, TypeError):
            return self._result(env if isinstance(env, dict) else {}, "DENIED", "malformed command", now)

    def handle_freeze(self, scope, ts, sig, now):
        pubs = self.trust.pubkeys_for(now)
        try:
            pubs["owner"].verify(bytes.fromhex(sig), f"freeze|{scope}|{ts}".encode())
        except (InvalidSignature, ValueError):
            return "DENY: freeze not signed by owner"
        if scope not in (self.node_id, "*") or abs(now - ts) > 120 or ts <= self.last_ctl:
            return "DENY: wrong scope, stale, or replayed"
        self.frozen, self.last_ctl = True, ts
        self._save()
        return "FROZEN: read-only"

    def handle_unfreeze(self, scope, ts, sig, ts2, sig2, now):
        pubs = self.trust.pubkeys_for(now)
        try:
            pubs["owner"].verify(bytes.fromhex(sig), f"unfreeze|{scope}|{ts}".encode())
            pubs["owner_confirm"].verify(bytes.fromhex(sig2), f"unfreeze_confirm|{scope}|{ts2}".encode())
        except (InvalidSignature, ValueError):
            return "DENY: unfreeze needs owner and owner_confirm"
        if scope not in (self.node_id, "*") or ts2 < ts + COOLOFF or ts <= self.last_ctl or now < ts2:
            return "DENY: scope, cooling-off, or replay check failed"
        self.frozen, self.last_ctl = False, ts
        self._save()
        return "UNFROZEN"


if __name__ == "__main__":
    from gibraltar import make_request, sign
    from omega_register import TrustRegistry, make_record, owner_sign

    T = 3_000_000
    K = {n: Ed25519PrivateKey.generate() for n in ["omega", "policy", "owner", "owner_confirm", "eu1"]}
    fixed = {n: K[n].public_key() for n in ["policy", "owner", "owner_confirm"]}
    trust = TrustRegistry(K["owner"].public_key(), fixed)
    rec = make_record(K["omega"].public_key(), T - 100)
    trust.register(rec, owner_sign(K["owner"], f"register|{digest(rec)}|{T}"), T)
    nodes = NodeRegistry(K["owner"].public_key())
    eu1 = NodeAgent("eu1", K["eu1"], trust)

    cert, pop = eu1.enroll_request("eu-west", T)
    print("enroll, no owner sig: ", nodes.enroll(cert, pop, "00" * 64, T)[1])
    print("enroll, bad PoP:      ", nodes.enroll(cert, "00" * 64, owner_sign(K["owner"], f"enroll|{digest(cert)}|{T}"), T)[1])
    print("enroll, valid:        ", nodes.enroll(cert, pop, owner_sign(K["owner"], f"enroll|{digest(cert)}|{T}"), T)[1])
    hb = eu1.heartbeat({"cpu": 0.2, "gpu": 0.0}, T)
    print("heartbeat:            ", nodes.verify_heartbeat(hb, now=T)[1])
    print("heartbeat replay:     ", nodes.verify_heartbeat(hb, last_seq=hb["seq"], now=T)[1])
    print("heartbeat tampered:   ", nodes.verify_heartbeat(dict(hb, metrics={"cpu": 0.0}), now=T)[1])

    seq = [0]

    def cmd(action, roles, node="eu1", snap="s1", ts=None, flags=()):
        action = dict(action, node=action.get("node", node))
        req = make_request(action, "spec", flags, snap, ttl=3600, now=T + 10)
        ap = [sign(r, K[r], req, (ts or {}).get(r, T + 11)) for r in roles]
        seq[0] += 1
        return {"node_id": node, "seq": seq[0], "request": req, "approvals": ap}

    now = T + 1000

    def run(label, env):
        r = eu1.handle_command(env, now)
        print(f"{label:30} -> {r['status']}: {r['detail']}")

    run("green read, Omega alone", cmd({"type": "read", "target": "eu1/state"}, ["omega"]))
    e = cmd({"type": "place", "target": "eu1/vr1"}, ["omega", "policy", "owner"])
    run("amber place, all keys", e)
    run("replay of same command", e)
    run("wrong node (action says us1)", cmd({"type": "place", "target": "us1/vr1", "node": "us1"}, ["omega", "policy", "owner"]))
    run("red delete, no confirm", cmd({"type": "delete", "target": "eu1/d"}, ["omega", "policy", "owner"]))
    run("red delete, full + cooloff", cmd({"type": "delete", "target": "eu1/d"}, ["omega", "policy", "owner", "owner_confirm"], ts={"owner_confirm": T + 500}))
    run("unknown action, all approved", cmd({"type": "key_rotate", "target": "eu1/k"}, ["omega", "policy", "owner", "owner_confirm"], ts={"owner_confirm": T + 500}))
    print("freeze, forged sig:   ->", eu1.handle_freeze("eu1", now, "00" * 64, now))
    print("freeze, owner:        ->", eu1.handle_freeze("eu1", now, owner_sign(K["owner"], f"freeze|eu1|{now}"), now))
    run("frozen: amber place", cmd({"type": "place", "target": "eu1/vr2"}, ["omega", "policy", "owner"]))
    run("frozen: green read", cmd({"type": "read", "target": "eu1/state"}, ["omega"]))
    u1, u2 = now + 1, now + 1 + COOLOFF
    print("unfreeze, owner only: ->", eu1.handle_unfreeze("eu1", u1, owner_sign(K["owner"], f"unfreeze|eu1|{u1}"), u1, "00" * 64, u2 + 1))
    print("unfreeze, both+cool:  ->", eu1.handle_unfreeze("eu1", u1, owner_sign(K["owner"], f"unfreeze|eu1|{u1}"), u2, owner_sign(K["owner_confirm"], f"unfreeze_confirm|eu1|{u2}"), u2 + 1))
