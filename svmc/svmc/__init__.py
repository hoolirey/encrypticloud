"""SVMC v0: Synthesized Virtual Machine Cloud, pure-Python local simulator.

Software simulations of virtualized hardware plus a policy/audit control
plane. Every part here is a data structure and a state machine; nothing
pretends to be real hardware.
"""

from svmc.audit import AuditRecorder, GENESIS_HASH
from svmc.advisor import WORKLOAD_PROFILES, ConfigurationAdvisor
from svmc.approval import ApprovalToken
from svmc.clock import VirtualClock, utcnow
from svmc.disk import VirtualEncryptedDisk
from svmc.exceptions import (
    ApprovalRequiredError,
    CapacityExceededError,
    ChainIntegrityError,
    IdentityError,
    NetworkDisabledError,
    NodeStateError,
    PolicyViolationError,
    SnapshotError,
    SvmcError,
)
from svmc.hardware import PAGE_BYTES, VirtualCPU, VirtualMemory
from svmc.identity import VirtualTPM
from svmc.network import IsolatedVirtualNetwork
from svmc.node import NodeConfiguration, NodeStatus, VirtualNode
from svmc.policy import PendingRequest, PolicyDecision, PolicyGate, PolicyLimits, RequestStatus
from svmc.snapshot import SnapshotManager

__version__ = "0.2.0"

__all__ = [
    "ApprovalRequiredError",
    "ApprovalToken",
    "AuditRecorder",
    "CapacityExceededError",
    "ChainIntegrityError",
    "ConfigurationAdvisor",
    "GENESIS_HASH",
    "IdentityError",
    "IsolatedVirtualNetwork",
    "NetworkDisabledError",
    "NodeConfiguration",
    "NodeStateError",
    "NodeStatus",
    "PAGE_BYTES",
    "PendingRequest",
    "PolicyDecision",
    "PolicyGate",
    "PolicyLimits",
    "PolicyViolationError",
    "RequestStatus",
    "SnapshotError",
    "SnapshotManager",
    "SvmcError",
    "VirtualCPU",
    "VirtualClock",
    "VirtualEncryptedDisk",
    "VirtualMemory",
    "VirtualNode",
    "VirtualTPM",
    "WORKLOAD_PROFILES",
    "utcnow",
]
