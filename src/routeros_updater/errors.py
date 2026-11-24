class UpdaterError(Exception):
    """A deliberately sanitized message safe to place in the audit trail."""


class TransportError(UpdaterError):
    pass


class IdentityError(UpdaterError):
    pass


class PolicyError(UpdaterError):
    pass


class BusyError(UpdaterError):
    pass


class WindowError(PolicyError):
    pass
