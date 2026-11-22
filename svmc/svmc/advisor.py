"""AI configuration advisor: proposes node configurations only.

This module has no import path to node construction or the audit record.
It returns data; only the policy gate can turn a proposal into a node.
"""

from __future__ import annotations

import secrets

from svmc.policy import PolicyLimits
from svmc.node import NodeConfiguration

WORKLOAD_PROFILES = {
    "inference": {"cores": 8, "memory_mib": 16384, "disk_mib": 256},
    "training": {"cores": 32, "memory_mib": 131072, "disk_mib": 512},
    "batch": {"cores": 4, "memory_mib": 8192, "disk_mib": 128},
    "generic": {"cores": 2, "memory_mib": 4096, "disk_mib": 32},
}


class ConfigurationAdvisor:
    def __init__(self, limits: PolicyLimits):
        self._limits = limits

    def propose(
        self,
        workload: str = "generic",
        valid_for_seconds: int | None = None,
    ) -> NodeConfiguration:
        if workload not in WORKLOAD_PROFILES:
            raise ValueError(
                f"unknown workload {workload!r}; expected one of {sorted(WORKLOAD_PROFILES)}"
            )
        profile = WORKLOAD_PROFILES[workload]
        return NodeConfiguration(
            name=f"{workload}-{secrets.token_hex(4)}",
            cores=min(profile["cores"], self._limits.max_cores),
            memory_mib=min(profile["memory_mib"], self._limits.max_memory_mib),
            disk_mib=min(profile["disk_mib"], self._limits.max_disk_mib),
            workload=workload,
            valid_for_seconds=valid_for_seconds,
        )
