"""Simulated CPU and memory with enforced usage limits."""

from __future__ import annotations

from svmc.exceptions import CapacityExceededError

PAGE_BYTES = 4096


class VirtualCPU:
    def __init__(self, core_count: int, usage_limit: int | None = None):
        if core_count < 1:
            raise ValueError("core_count must be >= 1")
        self.core_count = core_count
        self.usage_limit = core_count if usage_limit is None else usage_limit
        if self.usage_limit > core_count:
            raise ValueError("usage_limit cannot exceed core_count")
        self._in_use = 0

    @property
    def in_use(self) -> int:
        return self._in_use

    @property
    def available(self) -> int:
        return self.usage_limit - self._in_use

    def allocate(self, cores: int = 1) -> None:
        if cores < 1:
            raise ValueError("cores must be >= 1")
        if self._in_use + cores > self.usage_limit:
            raise CapacityExceededError(
                f"cpu limit: in_use={self._in_use} requested={cores} limit={self.usage_limit}"
            )
        self._in_use += cores

    def release(self, cores: int = 1) -> None:
        if cores < 1:
            raise ValueError("cores must be >= 1")
        if cores > self._in_use:
            raise ValueError(f"cannot release {cores} cores, only {self._in_use} in use")
        self._in_use -= cores


class VirtualMemory:
    def __init__(self, size_bytes: int, allocation_limit: int | None = None):
        if size_bytes < PAGE_BYTES:
            raise ValueError(f"size_bytes must be at least one page ({PAGE_BYTES})")
        self.size_bytes = size_bytes
        self.allocation_limit = size_bytes if allocation_limit is None else allocation_limit
        if self.allocation_limit > size_bytes:
            raise ValueError("allocation_limit cannot exceed size_bytes")
        self._allocated = 0

    @property
    def allocated(self) -> int:
        return self._allocated

    @property
    def available(self) -> int:
        return self.allocation_limit - self._allocated

    @property
    def used_pages(self) -> int:
        return (self._allocated + PAGE_BYTES - 1) // PAGE_BYTES

    def allocate(self, nbytes: int) -> int:
        if nbytes <= 0:
            raise ValueError("nbytes must be positive")
        if nbytes % PAGE_BYTES:
            nbytes += PAGE_BYTES - (nbytes % PAGE_BYTES)
        if self._allocated + nbytes > self.allocation_limit:
            raise CapacityExceededError(
                f"memory limit: allocated={self._allocated} requested={nbytes} "
                f"limit={self.allocation_limit}"
            )
        self._allocated += nbytes
        return self._allocated

    def free(self, nbytes: int) -> None:
        if nbytes <= 0:
            raise ValueError("nbytes must be positive")
        if nbytes % PAGE_BYTES:
            nbytes += PAGE_BYTES - (nbytes % PAGE_BYTES)
        if nbytes > self._allocated:
            raise ValueError(f"cannot free {nbytes} bytes, only {self._allocated} allocated")
        self._allocated -= nbytes
