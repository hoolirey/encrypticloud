"""Approval token issued only by the policy gate on explicit approval.

Direct construction raises; only ``svmc.policy.PolicyGate`` supplies the
private issuer key. This is a guard against accidental bypass, not a
security boundary: any Python code that deliberately imports
``svmc.approval._ISSUER`` can mint its own tokens. True enforcement is
impossible in-process in pure Python.
"""

from __future__ import annotations

from svmc.exceptions import ApprovalRequiredError

_ISSUER = object()


class ApprovalToken:
    __slots__ = ("request_id", "approver")

    def __init__(self, request_id: str, approver: str, issuer: object | None = None):
        if issuer is not _ISSUER:
            raise ApprovalRequiredError(
                "approval tokens can only be issued by svmc.policy.PolicyGate"
            )
        self.request_id = request_id
        self.approver = approver
