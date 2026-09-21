"""Cross-platform connection error classification."""

from __future__ import annotations

import errno
from dataclasses import dataclass

from rcscan.core.exceptions import RCScanError
from rcscan.network.models import PortState


class TargetExpansionError(RCScanError):
    """Authorized targets cannot be expanded within configured limits."""


class ScanExecutionError(RCScanError):
    """A scan execution option or invariant is invalid."""


@dataclass(frozen=True, slots=True)
class ClassifiedConnectionError:
    state: PortState
    code: int | None
    message: str
    retryable: bool
    exception_class: str
    errno_value: int | None
    winerror: int | None
    explicitly_unreachable: bool = False


_REFUSED_CODES = {
    errno.ECONNREFUSED,
    10061,  # WSAECONNREFUSED
    1225,  # ERROR_CONNECTION_REFUSED, used by Windows ConnectEx/IOCP
}
_TIMEOUT_CODES = {errno.ETIMEDOUT, 10060}
_UNREACHABLE_CODES = {
    errno.ENETDOWN,
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    10050,
    10051,
    10065,
}
_TRANSIENT_CODES = {
    errno.ECONNABORTED,
    errno.ECONNRESET,
    10053,
    10054,
}


def classify_connection_error(exc: BaseException) -> ClassifiedConnectionError:
    """Map Python/POSIX/Windows connect errors to conservative M2 states."""
    errno_value, winerror, code = _error_codes(exc)
    exception_class = exc.__class__.__name__
    if isinstance(exc, TimeoutError):
        return ClassifiedConnectionError(
            state=PortState.FILTERED,
            code=code,
            message="Connection timed out; no response was observed.",
            retryable=True,
            exception_class=exception_class,
            errno_value=errno_value,
            winerror=winerror,
        )

    if isinstance(exc, ConnectionRefusedError) or code in _REFUSED_CODES:
        return ClassifiedConnectionError(
            state=PortState.CLOSED,
            code=code,
            message="Connection refused.",
            retryable=False,
            exception_class=exception_class,
            errno_value=errno_value,
            winerror=winerror,
        )
    if code in _TIMEOUT_CODES:
        return ClassifiedConnectionError(
            state=PortState.FILTERED,
            code=code,
            message="Connection timed out; no response was observed.",
            retryable=True,
            exception_class=exception_class,
            errno_value=errno_value,
            winerror=winerror,
        )
    if code in _UNREACHABLE_CODES:
        return ClassifiedConnectionError(
            state=PortState.ERROR,
            code=code,
            message="The operating system reported the destination unreachable.",
            retryable=False,
            exception_class=exception_class,
            errno_value=errno_value,
            winerror=winerror,
            explicitly_unreachable=True,
        )
    return ClassifiedConnectionError(
        state=PortState.ERROR,
        code=code,
        message=_sanitize_message(exc),
        retryable=code in _TRANSIENT_CODES,
        exception_class=exception_class,
        errno_value=errno_value,
        winerror=winerror,
    )


def is_explicitly_unreachable(code: int | None) -> bool:
    """Return whether an OS error code explicitly reports no route/host."""
    return code in _UNREACHABLE_CODES


def _error_codes(exc: BaseException) -> tuple[int | None, int | None, int | None]:
    winerror = getattr(exc, "winerror", None)
    error_number = getattr(exc, "errno", None)
    normalized_winerror = winerror if isinstance(winerror, int) else None
    normalized_errno = error_number if isinstance(error_number, int) else None
    return (
        normalized_errno,
        normalized_winerror,
        normalized_winerror if normalized_winerror is not None else normalized_errno,
    )


def _sanitize_message(exc: BaseException) -> str:
    message = " ".join(str(exc).split())
    return (message or exc.__class__.__name__)[:200]
