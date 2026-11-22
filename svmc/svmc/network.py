"""Isolated virtual network: v0 nodes have no outbound network by design.

Every operation raises; there is no code path that opens a socket.
"""

from __future__ import annotations

from svmc.exceptions import NetworkDisabledError

_DISABLED = (
    "virtual network is disabled in svmc v0: "
    "nodes must not establish any inbound or outbound connection"
)


class IsolatedVirtualNetwork:
    enabled = False

    def connect(self, address: str, port: int) -> None:
        raise NetworkDisabledError(_DISABLED)

    def send(self, data: bytes) -> None:
        raise NetworkDisabledError(_DISABLED)

    def open_port(self, port: int) -> None:
        raise NetworkDisabledError(_DISABLED)

    def resolve(self, hostname: str) -> str:
        raise NetworkDisabledError(_DISABLED)
