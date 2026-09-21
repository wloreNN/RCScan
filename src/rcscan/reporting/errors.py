"""Expected reporting failures."""

from rcscan.core.exceptions import RCScanError


class ReportingError(RCScanError):
    """A requested report could not be rendered or written safely."""
