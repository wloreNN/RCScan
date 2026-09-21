"""Vulnerability intelligence errors that never expose provider secrets."""

from rcscan.core.exceptions import RCScanError


class VulnerabilityIntelligenceError(RCScanError):
    """Base error for optional vulnerability intelligence."""


class ProviderUnavailableError(VulnerabilityIntelligenceError):
    """The configured provider could not return trustworthy data."""


class ProviderRateLimitError(ProviderUnavailableError):
    """The provider rate limit prevented the lookup."""


class ProviderResponseError(ProviderUnavailableError):
    """The provider returned malformed or excessive data."""
