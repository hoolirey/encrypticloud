"""Policy gate: evaluates configurations and mediates every node lifecycle
transition. Node creation requires explicit human approval."""

from __future__ import annotations

import datetime
import logging
import secrets
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from svmc.approval import _ISSUER as _TOKEN_ISSUER
from svmc.approval import ApprovalToken
from svmc.audit import AuditRecorder
from svmc.clock import VirtualClock
from svmc.exceptions import NodeStateError, PolicyViolationError
from svmc.node import NodeConfiguration, VirtualNode
from svmc.snapshot import SnapshotManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicyLimits:
    max_cores: int = 64
    max_memory_mib: int = 262_144
    max_disk_mib: int = 1024
    max_validity_seconds: int = 30 * 24 * 3600


@dataclass(frozen=True)
class PolicyDecision:
    approved: bool
    reason: str


@dataclass
class PendingRequest:
    request_id: str
    config: NodeConfiguration
    proposed_by: str
    proposed_at: datetime.datetime
    status: "RequestStatus"
    decided_by: str | None = None
    decided_at: datetime.datetime | None = None
    reason: str | None = None


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PolicyGate:
    def __init__(
        self,
        limits: PolicyLimits,
        audit: AuditRecorder,
        clock: VirtualClock,
        base_dir: Path | str,
        snapshots: SnapshotManager | None = None,
    ):
        self.limits = limits
        self.audit = audit
        self.clock = clock
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._storage_dir = self.base_dir / "nodes"
        self._storage_dir.mkdir(exist_ok=True)
        self.snapshots = snapshots or SnapshotManager(self.base_dir / "snapshots")
        self._requests: dict[str, PendingRequest] = {}
        self._nodes: dict[str, VirtualNode] = {}

    def evaluate(self, config: NodeConfiguration) -> PolicyDecision:
        if not config.name or not config.name.strip():
            return PolicyDecision(False, "configuration name must not be empty")
        if config.cores < 1:
            return PolicyDecision(False, "cores must be >= 1")
        if config.cores > self.limits.max_cores:
            return PolicyDecision(
                False, f"cores {config.cores} exceeds limit {self.limits.max_cores}"
            )
        if config.memory_mib < 1:
            return PolicyDecision(False, "memory_mib must be >= 1")
        if config.memory_mib > self.limits.max_memory_mib:
            return PolicyDecision(
                False,
                f"memory_mib {config.memory_mib} exceeds limit {self.limits.max_memory_mib}",
            )
        if config.disk_mib < 1:
            return PolicyDecision(False, "disk_mib must be >= 1")
        if config.disk_mib > self.limits.max_disk_mib:
            return PolicyDecision(
                False, f"disk_mib {config.disk_mib} exceeds limit {self.limits.max_disk_mib}"
            )
        if config.valid_for_seconds is not None:
            if config.valid_for_seconds <= 0:
                return PolicyDecision(False, "valid_for_seconds must be positive")
            if config.valid_for_seconds > self.limits.max_validity_seconds:
                return PolicyDecision(
                    False,
                    f"valid_for_seconds {config.valid_for_seconds} exceeds limit "
                    f"{self.limits.max_validity_seconds}",
                )
        return PolicyDecision(True, "within policy limits")

    def submit(self, config: NodeConfiguration, proposed_by: str) -> str:
        decision = self.evaluate(config)
        if not decision.approved:
            self.audit.record(
                "node_submission_denied",
                actor=proposed_by,
                details={"reason": decision.reason, "config": _config_details(config)},
            )
            raise PolicyViolationError(decision.reason)
        request_id = "req-" + secrets.token_hex(8)
        self._requests[request_id] = PendingRequest(
            request_id=request_id,
            config=config,
            proposed_by=proposed_by,
            proposed_at=self.clock.now(),
            status=RequestStatus.PENDING,
        )
        self.audit.record(
            "node_proposed",
            actor=proposed_by,
            node_id=request_id,
            details=_config_details(config),
        )
        logger.info("request proposed id=%s by=%s", request_id, proposed_by)
        return request_id

    def get_request(self, request_id: str) -> PendingRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise NodeStateError(f"unknown request {request_id!r}")
        return request

    def approve(self, request_id: str, approver: str) -> VirtualNode:
        request = self.get_request(request_id)
        if request.status is not RequestStatus.PENDING:
            raise NodeStateError(
                f"request {request_id} is {request.status.value}, cannot approve"
            )
        decision = self.evaluate(request.config)
        if not decision.approved:
            raise PolicyViolationError(decision.reason)
        request.status = RequestStatus.APPROVED
        request.decided_by = approver
        request.decided_at = self.clock.now()
        self.audit.record(
            "node_approved", actor=approver, node_id=request_id, details={"approver": approver}
        )
        node = VirtualNode(
            request.config,
            self._storage_dir,
            self.clock,
            ApprovalToken(request_id, approver, issuer=_TOKEN_ISSUER),
        )
        self._nodes[node.id] = node
        self.audit.record(
            "node_created",
            actor=approver,
            node_id=node.id,
            details={"request_id": request_id, "config": _config_details(request.config)},
        )
        return node

    def reject(self, request_id: str, approver: str, reason: str) -> None:
        request = self.get_request(request_id)
        if request.status is not RequestStatus.PENDING:
            raise NodeStateError(
                f"request {request_id} is {request.status.value}, cannot reject"
            )
        request.status = RequestStatus.REJECTED
        request.decided_by = approver
        request.decided_at = self.clock.now()
        request.reason = reason
        self.audit.record(
            "node_rejected",
            actor=approver,
            node_id=request_id,
            details={"reason": reason, "config": _config_details(request.config)},
        )

    def destroy(self, node: VirtualNode, actor: str, reason: str = "") -> None:
        node.destroy()
        self.audit.record(
            "node_destroyed",
            actor=actor,
            node_id=node.id,
            details={"reason": reason, "request_id": node.request_id},
        )

    def snapshot(self, node: VirtualNode, actor: str, reason: str = "") -> str:
        snapshot_id = self.snapshots.save(node.snapshot_state())
        self.audit.record(
            "node_snapshot",
            actor=actor,
            node_id=node.id,
            details={"snapshot_id": snapshot_id, "reason": reason},
        )
        return snapshot_id

    def restore(self, snapshot_id: str, approver: str) -> VirtualNode:
        state = self.snapshots.load(snapshot_id)
        config = NodeConfiguration(**state["config"])
        node = VirtualNode(
            config,
            self._storage_dir,
            self.clock,
            ApprovalToken(f"restore:{snapshot_id}", approver, issuer=_TOKEN_ISSUER),
        )
        node.apply_restored_state(state)
        self._nodes[node.id] = node
        self.audit.record(
            "node_restored",
            actor=approver,
            node_id=node.id,
            details={"snapshot_id": snapshot_id},
        )
        return node

def _config_details(config: NodeConfiguration) -> dict[str, Any]:
    return asdict(config)
