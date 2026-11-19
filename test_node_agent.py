import os, tempfile, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from gibraltar import digest, make_request, sign
from omega_register import TrustRegistry, make_record, owner_sign
from node_agent import NodeAgent, NodeRegistry

T = 3_000_000
NOW = T + 1000


class Base(unittest.TestCase):
    def setUp(self):
        self.K = {n: Ed25519PrivateKey.generate() for n in ["omega", "policy", "owner", "owner_confirm", "eu1"]}
        fixed = {n: self.K[n].public_key() for n in ["policy", "owner", "owner_confirm"]}
        self.trust = TrustRegistry(self.K["owner"].public_key(), fixed)
        rec = make_record(self.K["omega"].public_key(), T - 100)
        self.trust.register(rec, owner_sign(self.K["owner"], f"register|{digest(rec)}|{T}"), T)
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "eu1.json")
        self.seq = 0

    def agent(self):
        return NodeAgent("eu1", self.K["eu1"], self.trust, state_path=self.path)

    def cmd(self, action, roles):
        action = dict(action, node="eu1")
        req = make_request(action, "spec", (), "s1", ttl=3600, now=T + 10)
        ap = [sign(r, self.K[r], req, T + 11) for r in roles]
        self.seq += 1
        return {"node_id": "eu1", "seq": self.seq, "request": req, "approvals": ap}


class Tests(Base):
    def test_expired_cert_rejected(self):
        a = self.agent()
        cert, pop = a.enroll_request("eu-west", T)
        cert["expires_at"] = T - 1
        reg = NodeRegistry(self.K["owner"].public_key())
        ok, why = reg.enroll(cert, pop, owner_sign(self.K["owner"], f"enroll|{digest(cert)}|{T}"), T)
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_replay_denied_after_restart(self):
        env = self.cmd({"type": "place", "target": "eu1/vr1"}, ["omega", "policy", "owner"])
        r1 = self.agent().handle_command(env, NOW)
        self.assertEqual(r1["status"], "EXECUTED")
        r2 = self.agent().handle_command(env, NOW)  # fresh agent, same state file
        self.assertEqual(r2["status"], "DENIED")

    def test_freeze_survives_restart(self):
        a = self.agent()
        a.handle_freeze("eu1", NOW, owner_sign(self.K["owner"], f"freeze|eu1|{NOW}"), NOW)
        env = self.cmd({"type": "place", "target": "eu1/vr2"}, ["omega", "policy", "owner"])
        r = self.agent().handle_command(env, NOW)
        self.assertEqual(r["status"], "DENIED")

    def test_heartbeat_seq_survives_restart(self):
        s1 = self.agent().heartbeat({"cpu": 0.1}, T)["seq"]
        s2 = self.agent().heartbeat({"cpu": 0.1}, T)["seq"]
        self.assertGreater(s2, s1)


if __name__ == "__main__":
    unittest.main()
