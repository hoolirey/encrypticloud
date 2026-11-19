"""Gibraltar: local approval demo CLI plus the library API used by node_agent.py."""
import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

HOME = Path.home() / ".gibraltar"
DB = HOME / "gibraltar.sqlite3"
KEYS = HOME / "keys"

COOLOFF_SECONDS = 300
COOLOFF = COOLOFF_SECONDS
ROLES = ("omega", "policy", "owner", "owner_confirm")

BASE_TIER = {
    "read": "GREEN",
    "health_check": "GREEN",
    "route": "GREEN",
    "workload_create": "AMBER",
    "scale": "AMBER",
    "place": "AMBER",
    "config_edit": "AMBER",
    "delete": "RED",
    "wipe": "RED",
    "key_rotate": "RED",
    "node_add": "RED",
    "node_remove": "RED",
    "gibraltar_edit": "RED",
}
SNAPSHOT_REQUIRED = {
    "config_edit", "delete", "wipe", "key_rotate",
    "node_remove", "gibraltar_edit",
}
RED_FLAGS = {
    "DESTRUCTIVE", "UNREVERSIBLE", "KEY_MATERIAL",
    "NEW_NODE", "PRIVILEGE_ESCALATION",
}
AMBER_FLAGS = {"EXTERNAL_EXPOSURE"}
REQUIRED = {
    "GREEN": ("omega",),
    "AMBER": ("omega", "policy", "owner"),
    "RED": ("omega", "policy", "owner", "owner_confirm"),
}


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def derive_flags(action, snapshot_id, omega_flags=()):
    flags = set(action.get("omega_flags", [])) | set(omega_flags or ())
    action_type = action["type"]
    params = action.get("params", {})

    if action_type in ("delete", "wipe"):
        flags.add("DESTRUCTIVE")
    if action_type in SNAPSHOT_REQUIRED and not snapshot_id:
        flags.add("UNREVERSIBLE")
    if action_type == "key_rotate":
        flags.add("KEY_MATERIAL")
    if action_type == "node_add":
        flags.add("NEW_NODE")
    if params.get("expose") is True:
        flags.add("EXTERNAL_EXPOSURE")
    if params.get("grant") is True:
        flags.add("PRIVILEGE_ESCALATION")

    return flags


def compute_tier(action, flags):
    tiers = ("GREEN", "AMBER", "RED")
    level = tiers.index(BASE_TIER.get(action["type"], "RED"))

    if flags & RED_FLAGS:
        level = 2
    if flags & AMBER_FLAGS:
        level = max(level, 1)
    if "ANOMALY" in flags or len(flags) >= 2:
        level = min(level + 1, 2)

    return tiers[level]


# ---- Library API used by node_agent.py -----------------------------------
def approval_message_ts(role, plan_hash, ts):
    return f"gibraltar-approval-v2|{role}|{plan_hash}|{ts}".encode("utf-8")


def make_request(action, spec_hash, flags, snapshot_id, ttl=900, now=None):
    now = int(time.time()) if now is None else now
    body = {
        "request_id": str(uuid.uuid4()),
        "nonce": uuid.uuid4().hex,
        "proposer": "omega",
        "created_at": now,
        "expires_at": now + ttl,
        "action": action,
        "spec_hash": spec_hash,
        "snapshot_id": snapshot_id,
        "omega_flags": sorted(flags),
    }
    body["plan_hash"] = digest(body)
    return body


def sign(role, private_key, req, ts):
    sig = private_key.sign(approval_message_ts(role, req["plan_hash"], ts)).hex()
    return {"role": role, "ts": ts, "sig": sig}


def authorize(req, approvals, pubkeys, used, now):
    """Stateless check. Burns the nonce in `used` on first sight, even if denied."""
    try:
        body = {k: v for k, v in req.items() if k != "plan_hash"}
        if digest(body) != req["plan_hash"]:
            return False, "DENY: request integrity check failed"
        if req["nonce"] in used:
            return False, "DENY: nonce already used (replay)"
        used.add(req["nonce"])
        if not req["created_at"] <= now <= req["expires_at"]:
            return False, "DENY: request expired or not yet valid"
        flags = derive_flags(req["action"], req["snapshot_id"], req["omega_flags"])
        tier = compute_tier(req["action"], flags)
        needed = REQUIRED[tier]
        by_role = {}
        for a in approvals:
            if a["role"] in by_role:
                return False, f"DENY: duplicate approval for {a['role']}"
            by_role[a["role"]] = a
        unexpected = set(by_role) - set(needed)
        if unexpected:
            return False, f"DENY: unexpected approvals: {sorted(unexpected)}"
        missing = [r for r in needed if r not in by_role]
        if missing:
            return False, f"DENY {tier}: missing {', '.join(missing)}"
        raw = {}
        for role in needed:
            pub = pubkeys.get(role)
            if pub is None:
                return False, f"DENY: no public key for {role}"
            raw[role] = pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if len(set(raw.values())) != len(needed):
            return False, "DENY: required roles must use distinct keys"
        for role in needed:
            a = by_role[role]
            if not req["created_at"] <= a["ts"] <= now:
                return False, f"DENY: invalid approval time for {role}"
            try:
                pubkeys[role].verify(
                    bytes.fromhex(a["sig"]),
                    approval_message_ts(role, req["plan_hash"], a["ts"]))
            except (InvalidSignature, ValueError):
                return False, f"DENY: invalid signature for {role}"
        if tier == "RED" and by_role["owner_confirm"]["ts"] < by_role["owner"]["ts"] + COOLOFF:
            return False, "DENY RED: cooloff not satisfied"
        return True, f"AUTHORIZED {tier}"
    except (KeyError, TypeError, AttributeError):
        return False, "DENY: malformed request or approvals"
