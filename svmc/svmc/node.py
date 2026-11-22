"""Virtual node: composition of the simulated hardware parts and lifecycle."""

from __future__ import annotations

import datetime
import logging
import secrets
import shutil
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

from svmc.approval import ApprovalToken
from svmc.clock import VirtualClock
from svmc.disk import VirtualEncryptedDisk
from svmc.exceptions import ApprovalRequiredError, NodeStateError
from svmc.hardware import VirtualCPU, VirtualMemory
from svmc.identity import VirtualTPM
from svmc.network import IsolatedVirtualNetwork

logger = logging.getLogger(__name__)


class NodeStatus(str, Enum):
    CREATED = "created"
    DESTROYED = "destroyed"


@dataclass
class NodeConfiguration:
    name: str
    cores: int
    memory_mib: int
    disk_mib: int
    workload: str = "generic"
    valid_for_seconds: int | None = None


class VirtualNode:
    def __init__(
        self,
        config: NodeConfiguration,
        base_dir: Path | str,
        clock: VirtualClock,
        approval: ApprovalToken,
    ):
        if not isinstance(approval, ApprovalToken):
            raise ApprovalRequiredError(
                "node creation requires an approval token from the policy gate"
            )
        if config.valid_for_seconds is not None and config.valid_for_seconds <= 0:
            raise ValueError("valid_for_seconds must be positive")
        self.id = "node-" + secrets.token_hex(8)
        self.config = config
        self.clock = clock
        self.status = NodeStatus.CREATED
        self.created_at = clock.now()
        self.destroyed_at: datetime.datetime | None = None
        self.approved_by = approval.approver
        self.request_id = approval.request_id
        self.expires_at = (
            None
            if config.valid_for_seconds is None
            else self.created_at + datetime.timedelta(seconds=config.valid_for_seconds)
        )
        self.base_dir = Path(base_dir) / self.id
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.cpu = VirtualCPU(config.cores)
        self.memory = VirtualMemory(config.memory_mib * 1024 * 1024)
        self.disk = VirtualEncryptedDisk(
            self.base_dir / "storage", secrets.token_bytes(32), config.disk_mib * 1024 * 1024
        )
        self.tpm = VirtualTPM(self.id)
        self.tpm.provision()
        self.network = IsolatedVirtualNetwork()
        logger.info("node created id=%s name=%s cores=%d", self.id, config.name, config.cores)

    def _require_live(self) -> None:
        if self.status is NodeStatus.DESTROYED:
            raise NodeStateError(f"node {self.id} is destroyed")

    def start_workload(self, cores: int, memory_bytes: int) -> None:
        self._require_live()
        self.cpu.allocate(cores)
        try:
            self.memory.allocate(memory_bytes)
        except Exception:
            self.cpu.release(cores)
            raise

    def write_file(self, name: str, data: bytes | str) -> Path:
        self._require_live()
        return self.disk.write_file(name, data)

    def read_file(self, name: str) -> bytes:
        self._require_live()
        return self.disk.read_file(name)

    def stop_workload(self, cores: int, memory_bytes: int) -> None:
        self._require_live()
        self.memory.free(memory_bytes)
        self.cpu.release(cores)

    def is_expired(self) -> bool:
        return self.expires_at is not None and self.clock.now() >= self.expires_at

    def snapshot_state(self) -> dict:
        self._require_live()
        return {
            "id": self.id,
            "config": asdict(self.config),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "cpu": {
                "core_count": self.cpu.core_count,
                "usage_limit": self.cpu.usage_limit,
                "in_use": self.cpu.in_use,
            },
            "memory": {
                "size_bytes": self.memory.size_bytes,
                "allocation_limit": self.memory.allocation_limit,
                "allocated": self.memory.allocated,
            },
            "tpm": {"generation": self.tpm.generation, "pcrs": dict(self.tpm.pcrs)},
        }

    def apply_restored_state(self, state: dict) -> None:
        self._require_live()
        cpu_state = state["cpu"]
        self.cpu = VirtualCPU(cpu_state["core_count"], cpu_state["usage_limit"])
        if cpu_state["in_use"]:
            self.cpu.allocate(cpu_state["in_use"])
        memory_state = state["memory"]
        self.memory = VirtualMemory(memory_state["size_bytes"], memory_state["allocation_limit"])
        if memory_state["allocated"]:
            self.memory.allocate(memory_state["allocated"])
        self.tpm.generation = state["tpm"]["generation"]
        self.tpm.pcrs = {int(k): v for k, v in state["tpm"]["pcrs"].items()}
        self.created_at = datetime.datetime.fromisoformat(state["created_at"])
        self.expires_at = (
            datetime.datetime.fromisoformat(state["expires_at"]) if state["expires_at"] else None
        )

    def destroy(self) -> None:
        self._require_live()
        if self.disk.root.exists():
            for path in sorted(self.disk.root.rglob("*")):
                if path.is_file():
                    self.disk.secure_delete(path)
            shutil.rmtree(self.disk.root)
        shutil.rmtree(self.base_dir)
        self.tpm.destroy()
        self.status = NodeStatus.DESTROYED
        self.destroyed_at = self.clock.now()
        logger.info("node destroyed id=%s", self.id)
