"""Centralized secret redaction for all report formats."""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "x_api_key",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
}
_SENSITIVE_KEY_PARTS = ("password", "passwd", "secret", "token", "api_key", "apikey")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]+=*")
_HEADER_SECRET = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|api-key)\s*([:=])\s*([^\s,;]+)"
)
_KEY_VALUE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|"
    r"api_key|apikey|client_secret|secret)=([^&\s]+)"
)
_JSON_SECRET = re.compile(
    r"""(?ix)
    (["']?(?:password|passwd|pwd|token|access_token|refresh_token|
    api_key|apikey|client_secret|secret)["']?\s*:\s*)
    (["'])[^"']*\2
    """
)


def is_sensitive_name(name: str) -> bool:
    normalized = name.strip().casefold().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def sanitize_value(value: str, *, name: str | None = None) -> str:
    if name is not None and is_sensitive_name(name):
        return REDACTED
    return sanitize_text(value)


def sanitize_text(value: str) -> str:
    sanitized = _BEARER.sub(REDACTED, value)
    sanitized = _HEADER_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}",
        sanitized,
    )
    sanitized = _KEY_VALUE_SECRET.sub(
        lambda match: f"{match.group(1)}={REDACTED}",
        sanitized,
    )
    return _JSON_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(2)}",
        sanitized,
    )


def sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        pairs = [
            (name, sanitize_value(item, name=name))
            for name, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(pairs, doseq=True),
                "",
            )
        )
    except (UnicodeError, ValueError):
        return sanitize_text(value)


def sanitize_mapping(values: Mapping[str, str]) -> dict[str, str]:
    return {
        sanitize_text(str(name))[:200]: sanitize_value(str(value), name=str(name))[:2_000]
        for name, value in sorted(values.items(), key=lambda item: str(item[0]).casefold())
    }
