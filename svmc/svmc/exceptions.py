"""Exception hierarchy for SVMC v0."""


class SvmcError(Exception):
    """Base class for all SVMC errors."""


class CapacityExceededError(SvmcError):
    """A virtual resource limit was exceeded."""


class NetworkDisabledError(SvmcError):
    """A network operation was attempted while the virtual network is disabled."""


class PolicyViolationError(SvmcError):
    """A configuration violated policy limits."""


class ApprovalRequiredError(SvmcError):
    """Node creation was attempted without an explicit approval token."""


class NodeStateError(SvmcError):
    """An operation was invalid for the node's current lifecycle state."""


class IdentityError(SvmcError):
    """A virtual TPM operation violated its key lifecycle rules."""


class SnapshotError(SvmcError):
    """A snapshot could not be loaded or applied."""


class ChainIntegrityError(SvmcError):
    """The append-only audit chain failed verification."""
