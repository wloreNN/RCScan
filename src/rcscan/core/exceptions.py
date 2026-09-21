"""Domain exceptions displayed to CLI users without tracebacks."""


class RCScanError(Exception):
    """Base class for expected RCScan errors."""


class ConfigurationError(RCScanError):
    """Configuration is missing, unreadable, or invalid."""


class TargetValidationError(RCScanError):
    """A target value is invalid."""


class ScopeValidationError(RCScanError):
    """A target is not permitted by the explicit scope."""


class AuthorizationError(RCScanError):
    """The operator has not confirmed authorization."""


class PortValidationError(RCScanError):
    """A port specification is invalid."""
