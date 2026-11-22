"""Test suite for SVMC v0."""

from __future__ import annotations

import datetime
import tempfile
import unittest
from pathlib import Path

from svmc import (
    ApprovalRequiredError,
    ApprovalToken,
    AuditRecorder,
    CapacityExceededError,
    ChainIntegrityError,
    ConfigurationAdvisor,
    GENESIS_HASH,
    IdentityError,
    IsolatedVirtualNetwork,
    NetworkDisabledError,
    NodeConfiguration,
    NodeStateError,
    PolicyGate,
    PolicyLimits,
    PolicyViolationError,
    SnapshotError,
    VirtualClock,
    VirtualCPU,
    VirtualEncryptedDisk,
    VirtualMemory,
    VirtualTPM,
    WORKLOAD_PROFILES,
)


def make_config(**overrides):
    fields = {
        "name": "test-node",
        "cores": 4,
        "memory_mib": 1024,
        "disk_mib": 32,
        "workload": "generic",
        "valid_for_seconds": 3600,
    }
    fields.update(overrides)
    return NodeConfiguration(**fields)


class TestVirtualCPU(unittest.TestCase):
    def test_allocate_within_limit(self):
        cpu = VirtualCPU(core_count=4)
        cpu.allocate(2)
        cpu.allocate(1)
        self.assertEqual(cpu.in_use, 3)
        self.assertEqual(cpu.available, 1)

    def test_limit_enforced(self):
        cpu = VirtualCPU(core_count=4, usage_limit=2)
        cpu.allocate(2)
        with self.assertRaises(CapacityExceededError):
            cpu.allocate(1)
        cpu.release(1)
        cpu.allocate(1)
        self.assertEqual(cpu.in_use, 2)

    def test_usage_limit_cannot_exceed_core_count(self):
        with self.assertRaises(ValueError):
            VirtualCPU(core_count=2, usage_limit=4)

    def test_release_validation(self):
        cpu = VirtualCPU(core_count=2)
        with self.assertRaises(ValueError):
            cpu.release(1)
        cpu.allocate(1)
        with self.assertRaises(ValueError):
            cpu.release(2)


class TestVirtualMemory(unittest.TestCase):
    def test_page_rounding(self):
        mem = VirtualMemory(size_bytes=16 * 4096)
        mem.allocate(100)
        self.assertEqual(mem.allocated, 4096)
        self.assertEqual(mem.used_pages, 1)

    def test_allocation_limit_enforced(self):
        mem = VirtualMemory(size_bytes=8 * 4096, allocation_limit=2 * 4096)
        mem.allocate(4096)
        mem.allocate(4096)
        with self.assertRaises(CapacityExceededError):
            mem.allocate(4096)
        mem.free(4096)
        mem.allocate(4096)
        with self.assertRaises(CapacityExceededError):
            mem.allocate(8192)


class TestVirtualEncryptedDisk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = b"k" * 32
        self.disk = VirtualEncryptedDisk(
            Path(self.tmp.name) / "storage", key, max_bytes=64 * 1024
        )

    def test_roundtrip(self):
        self.disk.write_file("notes.txt", "secret payload")
        self.disk.write_file("blob.bin", bytes(range(256)))
        self.assertEqual(self.disk.read_file("notes.txt"), b"secret payload")
        self.assertEqual(self.disk.read_file("blob.bin"), bytes(range(256)))
        self.assertEqual(self.disk.list_files(), ["blob.bin", "notes.txt"])

    def test_no_plaintext_on_disk(self):
        self.disk.write_file("secret.txt", "TOPSECRET-PLAINTEXT")
        raw = (Path(self.tmp.name) / "storage" / "secret.txt").read_bytes()
        self.assertNotIn(b"TOPSECRET-PLAINTEXT", raw)
        self.assertTrue(raw.startswith(VirtualEncryptedDisk.HEADER))

    def test_limit_enforced(self):
        disk = VirtualEncryptedDisk(
            Path(self.tmp.name) / "small", b"k" * 32, max_bytes=1024
        )
        with self.assertRaises(CapacityExceededError):
            disk.write_file("big.bin", b"x" * 4096)
        disk.write_file("ok.bin", b"y" * 100)

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.disk.write_file("../escape.txt", "no")
        with self.assertRaises(ValueError):
            self.disk.write_file("sub/dir.txt", "no")

    def test_missing_file(self):
        self.assertRaises(FileNotFoundError, self.disk.read_file, "absent.txt")

    def test_wrong_key_rejects_integrity(self):
        self.disk.write_file("a.txt", "x")
        other = VirtualEncryptedDisk(
            self.disk.root, b"z" * 32, max_bytes=64 * 1024
        )
        with self.assertRaises(ValueError):
            other.read_file("a.txt")

    def test_secure_delete_and_wipe(self):
        path = self.disk.write_file("gone.txt", "bye")
        self.disk.secure_delete("gone.txt")
        self.assertFalse(path.exists())
        self.disk.write_file("a.txt", "1")
        self.disk.write_file("b.txt", "2")
        self.disk.wipe()
        self.assertEqual(self.disk.list_files(), [])
        self.assertEqual(self.disk.used_bytes, 0)


class TestVirtualTPM(unittest.TestCase):
    def setUp(self):
        self.tpm = VirtualTPM("node-abc")
        self.tpm.provision()

    def test_provision_and_attest(self):
        attestation = self.tpm.attest(b"\x01" * 32)
        self.assertEqual(attestation["node_id"], "node-abc")
        self.assertEqual(attestation["generation"], 1)
        self.assertTrue(self.tpm.verify_attestation(attestation))

    def test_wrong_nonce_fails_verification(self):
        attestation = self.tpm.attest(b"\x01" * 32)
        forged = dict(attestation, nonce=(b"\x02" * 32).hex())
        self.assertFalse(self.tpm.verify_attestation(forged))

    def test_rotate_increments_generation_and_blocks_old(self):
        old = self.tpm.attest(b"\x01" * 32)
        self.tpm.rotate()
        self.assertEqual(self.tpm.generation, 2)
        self.assertFalse(self.tpm.verify_attestation(old))
        self.assertTrue(self.tpm.verify_attestation(self.tpm.attest(b"\x01" * 32)))

    def test_pcr_chaining(self):
        first = self.tpm.measure(3, b"boot")
        second = self.tpm.measure(3, b"app")
        self.assertNotEqual(first, second)
        self.assertEqual(self.tpm.pcrs[3], second)

    def test_double_provision_rejected(self):
        with self.assertRaises(IdentityError):
            self.tpm.provision()

    def test_destroy_zeroizes_and_blocks(self):
        self.tpm.destroy()
        with self.assertRaises(IdentityError):
            self.tpm.attest(b"\x00" * 32)
        with self.assertRaises(IdentityError):
            self.tpm.rotate()
        with self.assertRaises(IdentityError):
            self.tpm.provision()


class TestIsolatedNetwork(unittest.TestCase):
    def test_every_operation_raises(self):
        net = IsolatedVirtualNetwork()
        self.assertFalse(net.enabled)
        for call in (
            lambda: net.connect("10.0.0.1", 443),
            lambda: net.send(b"x"),
            lambda: net.open_port(8080),
            lambda: net.resolve("example.invalid"),
        ):
            with self.assertRaises(NetworkDisabledError):
                call()


class TestVirtualClock(unittest.TestCase):
    def test_advance_and_set(self):
        clock = VirtualClock()
        start = clock.now()
        clock.advance(90)
        self.assertEqual(clock.now() - start, datetime.timedelta(seconds=90))
        moment = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        clock.set(moment)
        self.assertEqual(clock.now(), moment)
        with self.assertRaises(ValueError):
            clock.set(datetime.datetime(2030, 1, 1))


class TestAuditRecorder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = AuditRecorder(str(Path(self.tmp.name) / "audit.db"))
        self.addCleanup(self.audit.close)

    def test_append_and_query(self):
        self.audit.record("node_proposed", actor="advisor", node_id="req-1", details={"a": 1})
        self.audit.record("node_approved", actor="alice", node_id="req-1", details={})
        third_id = self.audit.record("node_created", actor="alice", node_id="node-1")
        self.assertEqual(third_id, 3)
        self.assertEqual(len(self.audit.events()), 3)
        self.assertEqual(len(self.audit.events(node_id="req-1")), 2)
        self.assertEqual(len(self.audit.events(action="node_created")), 1)
        self.assertTrue(self.audit.verify_chain())

    def test_genesis_and_chain_links(self):
        self.audit.record("a", actor="x")
        self.audit.record("b", actor="y")
        rows = self.audit._conn.execute(
            "SELECT seq, prev_hash, hash FROM audit_events ORDER BY seq"
        ).fetchall()
        self.assertEqual(rows[0][1], GENESIS_HASH)
        self.assertEqual(rows[1][1], rows[0][2])

    def test_tamper_detected(self):
        self.audit.record("node_proposed", actor="advisor", node_id="req-1")
        self.audit.record("node_approved", actor="alice", node_id="req-1")
        self.assertTrue(self.audit.verify_chain())
        self.audit._conn.execute(
            "UPDATE audit_events SET actor = 'mallory' WHERE seq = 2"
        )
        self.audit._conn.commit()
        with self.assertRaises(ChainIntegrityError):
            self.audit.verify_chain()


class TestConfigurationAdvisor(unittest.TestCase):
    def test_proposes_profile(self):
        advisor = ConfigurationAdvisor(PolicyLimits())
        config = advisor.propose("inference", valid_for_seconds=600)
        self.assertTrue(config.name.startswith("inference-"))
        self.assertEqual(config.cores, 8)
        self.assertEqual(config.memory_mib, 16384)
        self.assertEqual(config.valid_for_seconds, 600)

    def test_proposals_clamped_to_limits(self):
        advisor = ConfigurationAdvisor(PolicyLimits(max_cores=16, max_memory_mib=8192))
        config = advisor.propose("training")
        self.assertLessEqual(config.cores, 16)
        self.assertLessEqual(config.memory_mib, 8192)

    def test_unknown_workload(self):
        advisor = ConfigurationAdvisor(PolicyLimits())
        with self.assertRaises(ValueError):
            advisor.propose("quantum")

    def test_advisor_cannot_create_nodes(self):
        advisor = ConfigurationAdvisor(PolicyLimits())
        for forbidden in ("approve", "submit", "create", "create_node", "destroy"):
            self.assertFalse(hasattr(advisor, forbidden))
        config = advisor.propose("batch")
        self.assertIsInstance(config, NodeConfiguration)


class TestPolicyGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = VirtualClock()
        self.audit = AuditRecorder(str(self.base / "audit.db"))
        self.addCleanup(self.audit.close)
        self.gate = PolicyGate(PolicyLimits(), self.audit, self.clock, self.base)

    def test_rejects_over_limit_before_anything_is_created(self):
        with self.assertRaises(PolicyViolationError):
            self.gate.submit(make_config(cores=128), proposed_by="advisor")
        self.assertEqual(self.audit.events(action="node_proposed"), [])
        self.assertEqual(self.audit.events(action="node_submission_denied")[0]["details"]["reason"],
                         "cores 128 exceeds limit 64")

    def test_direct_token_construction_rejected(self):
        with self.assertRaises(ApprovalRequiredError):
            ApprovalToken("req-forged", "attacker")
        with self.assertRaises(ApprovalRequiredError):
            ApprovalToken("req-forged", "attacker", issuer=object())

    def test_missing_approval_token_blocks_construction(self):
        with self.assertRaises(ApprovalRequiredError):
            from svmc import VirtualNode
            VirtualNode(make_config(), self.base / "nodes", self.clock, None)

    def test_submit_approve_creates_node(self):
        config = make_config(valid_for_seconds=60)
        request_id = self.gate.submit(config, proposed_by="advisor")
        node = self.gate.approve(request_id, approver="alice")
        self.assertEqual(node.status.value, "created")
        self.assertEqual(node.approved_by, "alice")
        self.assertEqual(node.request_id, request_id)
        self.assertEqual(node.config, config)
        self.assertEqual(node.tpm.generation, 1)
        actions = [e["action"] for e in self.audit.events()]
        self.assertEqual(
            actions, ["node_proposed", "node_approved", "node_created"]
        )

    def test_reject_no_node(self):
        request_id = self.gate.submit(make_config(), proposed_by="advisor")
        self.gate.reject(request_id, approver="bob", reason="over budget")
        actions = [e["action"] for e in self.audit.events()]
        self.assertEqual(actions, ["node_proposed", "node_rejected"])
        with self.assertRaises(NodeStateError):
            self.gate.approve(request_id, approver="alice")

    def test_double_decision_blocked(self):
        request_id = self.gate.submit(make_config(), proposed_by="advisor")
        node = self.gate.approve(request_id, approver="alice")
        with self.assertRaises(NodeStateError):
            self.gate.approve(request_id, approver="bob")
        with self.assertRaises(NodeStateError):
            self.gate.reject(request_id, approver="bob", reason="late")
        self.gate.destroy(node, actor="alice")

    def test_missing_request(self):
        with self.assertRaises(NodeStateError):
            self.gate.approve("req-does-not-exist", approver="alice")

    def test_expiry_via_virtual_clock(self):
        config = make_config(valid_for_seconds=60)
        request_id = self.gate.submit(config, proposed_by="advisor")
        node = self.gate.approve(request_id, approver="alice")
        self.assertFalse(node.is_expired())
        self.clock.advance(59)
        self.assertFalse(node.is_expired())
        self.clock.advance(1)
        self.assertTrue(node.is_expired())


class TestSnapshotRestore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = VirtualClock()
        self.audit = AuditRecorder(str(self.base / "audit.db"))
        self.addCleanup(self.audit.close)
        self.gate = PolicyGate(PolicyLimits(), self.audit, self.clock, self.base)

    def _make_node(self):
        request_id = self.gate.submit(make_config(), proposed_by="advisor")
        node = self.gate.approve(request_id, approver="alice")
        node.start_workload(cores=2, memory_bytes=128 * 1024 * 1024)
        node.disk.write_file("state.txt", "snapshotted secret")
        node.tpm.measure(5, b"boot-event")
        return node

    def test_save_restore_fidelity(self):
        node = self._make_node()
        snapshot_id = self.gate.snapshot(node, actor="alice", reason="before test")
        restored = self.gate.restore(snapshot_id, approver="bob")
        self.assertEqual(restored.config, node.config)
        self.assertEqual(restored.cpu.in_use, 2)
        self.assertEqual(restored.cpu.core_count, node.cpu.core_count)
        self.assertEqual(restored.memory.allocated, 128 * 1024 * 1024)
        self.assertEqual(restored.tpm.generation, node.tpm.generation)
        self.assertEqual(restored.tpm.pcrs, node.tpm.pcrs)
        self.assertEqual(restored.expires_at, node.expires_at)
        actions = [e["action"] for e in self.audit.events()]
        self.assertIn("node_snapshot", actions)
        self.assertIn("node_restored", actions)

    def test_reset_to_snapshot(self):
        node = self._make_node()
        snapshot_id = self.gate.snapshot(node, actor="alice")
        node.stop_workload(cores=2, memory_bytes=128 * 1024 * 1024)
        node.tpm.rotate()
        self.assertEqual(node.tpm.generation, 2)
        reset = self.gate.restore(snapshot_id, approver="bob")
        self.assertEqual(reset.tpm.generation, 1)
        self.assertNotEqual(reset.tpm.generation, node.tpm.generation)
        self.assertEqual(reset.pcrs if hasattr(reset, "pcrs") else reset.tpm.pcrs,
                         {0: node.tpm.pcrs[0], 5: node.tpm.pcrs[5]})

    def test_unknown_snapshot(self):
        with self.assertRaises(SnapshotError):
            self.gate.restore("snap-missing", approver="bob")


class TestEndToEnd(unittest.TestCase):
    def test_full_lifecycle_with_cleanup(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        clock = VirtualClock()
        audit = AuditRecorder(str(base / "audit.db"))
        self.addCleanup(audit.close)
        gate = PolicyGate(PolicyLimits(max_validity_seconds=3600), audit, clock, base)
        with self.assertRaises(PolicyViolationError):
            gate.submit(make_config(valid_for_seconds=7200), proposed_by="advisor")
        advisor = ConfigurationAdvisor(PolicyLimits(max_validity_seconds=3600))
        config = advisor.propose("batch", valid_for_seconds=600)
        request_id = gate.submit(config, proposed_by="advisor")
        node = gate.approve(request_id, approver="ops")
        node.start_workload(cores=1, memory_bytes=64 * 1024 * 1024)
        node.disk.write_file("synthetic.bin", "synthetic-data-only")

        with self.assertRaises(NetworkDisabledError):
            node.network.connect("10.0.0.1", 443)

        snapshot_id = gate.snapshot(node, actor="ops", reason="pre-expiry")
        clock.advance(600)
        self.assertTrue(node.is_expired())
        gate.destroy(node, actor="ops", reason="expired")
        with self.assertRaises(NodeStateError):
            node.write_file("after.txt", "no")
        with self.assertRaises(IdentityError):
            node.tpm.attest(b"\x00" * 32)
        self.assertFalse(node.base_dir.exists())

        restored = gate.restore(snapshot_id, approver="ops")
        self.assertEqual(restored.cpu.in_use, 1)
        self.assertTrue(restored.is_expired())

        actions = [e["action"] for e in audit.events()]
        self.assertEqual(
            actions,
            [
                "node_submission_denied",
                "node_proposed",
                "node_approved",
                "node_created",
                "node_snapshot",
                "node_destroyed",
                "node_restored",
            ],
        )
        self.assertTrue(audit.verify_chain())


if __name__ == "__main__":
    unittest.main()
