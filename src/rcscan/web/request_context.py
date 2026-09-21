"""Origin-bound static authentication and secret-safe web request context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from rcscan.core.exceptions import RCScanError

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_BLOCKED_HEADERS = {
    "connection",
    "content-length",
    "cookie",
    "host",
    "transfer-encoding",
}
_REDACTED = "[REDACTED]"


class AuthenticationInputError(RCScanError):
    """Static authentication input is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class StaticHeader:
    name: str
    _value: str = field(repr=False)

    @property
    def value(self) -> str:
        return self._value


@dataclass(frozen=True, slots=True)
class StaticCookie:
    name: str
    _value: str = field(repr=False)

    @property
    def value(self) -> str:
        return self._value


@dataclass(frozen=True, slots=True)
class StaticAuthentication:
    headers: tuple[StaticHeader, ...] = ()
    cookies: tuple[StaticCookie, ...] = ()

    @property
    def configured(self) -> bool:
        return bool(self.headers or self.cookies)

    @property
    def header_names(self) -> tuple[str, ...]:
        names = [header.name for header in self.headers]
        if self.cookies:
            names.append("Cookie")
        return tuple(names)

    def __repr__(self) -> str:
        return (
            "StaticAuthentication("
            f"configured={self.configured}, header_names={self.header_names!r})"
        )


class WebRequestContext:
    """Apply static secrets only to explicitly registered web origins."""

    def __init__(self, authentication: StaticAuthentication | None = None) -> None:
        self._authentication = authentication or StaticAuthentication()
        self._origins: set[str] = set()
        self._secret_values = tuple(
            sorted(
                {
                    item
                    for item in (
                        *(
                            secret
                            for header in self._authentication.headers
                            for secret in _header_secrets(header)
                        ),
                        *(cookie.value for cookie in self._authentication.cookies),
                    )
                    if item
                },
                key=len,
                reverse=True,
            )
        )

    @property
    def authentication_configured(self) -> bool:
        return self._authentication.configured

    @property
    def authentication_header_names(self) -> tuple[str, ...]:
        return self._authentication.header_names

    def register_origin(self, origin: str) -> None:
        normalized = normalized_origin(origin)
        if normalized is not None:
            self._origins.add(normalized)

    def headers_for(self, url: str) -> tuple[tuple[str, str], ...]:
        origin = normalized_origin(url)
        if origin is None or origin not in self._origins:
            return ()
        headers = [
            (header.name, header.value)
            for header in self._authentication.headers
        ]
        if self._authentication.cookies:
            headers.append(
                (
                    "Cookie",
                    "; ".join(
                        f"{cookie.name}={cookie.value}"
                        for cookie in self._authentication.cookies
                    ),
                )
            )
        return tuple(headers)

    def redact_text(self, value: str) -> str:
        result = value
        for secret in self._secret_values:
            result = result.replace(secret, _REDACTED)
        return result

    def redact_bytes(self, value: bytes) -> bytes:
        result = value
        for secret in self._secret_values:
            encoded = secret.encode("latin-1", errors="ignore")
            if encoded:
                result = result.replace(encoded, _REDACTED.encode("ascii"))
        return result

    def __repr__(self) -> str:
        return (
            "WebRequestContext("
            f"authentication_configured={self.authentication_configured}, "
            f"registered_origins={len(self._origins)})"
        )


def parse_static_authentication(
    header_values: list[str] | tuple[str, ...] | None,
    cookie_values: list[str] | tuple[str, ...] | None,
) -> StaticAuthentication:
    headers = tuple(_parse_header(value) for value in (header_values or ()))
    cookies = tuple(_parse_cookie(value) for value in (cookie_values or ()))
    cookie_names = [cookie.name.casefold() for cookie in cookies]
    if len(cookie_names) != len(set(cookie_names)):
        raise AuthenticationInputError(
            "Static cookie names must be unique; a supplied value was not displayed."
        )
    return StaticAuthentication(headers=headers, cookies=cookies)


def normalized_origin(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            return None
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        return f"{parsed.scheme.casefold()}://{parsed.hostname.casefold()}:{port}"
    except ValueError:
        return None


def _parse_header(value: str) -> StaticHeader:
    if ":" not in value:
        raise AuthenticationInputError(
            "Invalid --header input; expected 'Name: Value'. The supplied value was not displayed."
        )
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not _HEADER_NAME.fullmatch(name):
        raise AuthenticationInputError(
            "Invalid --header name; the supplied value was not displayed."
        )
    if name.casefold() in _BLOCKED_HEADERS:
        raise AuthenticationInputError(
            "The requested header is managed by RCScan and cannot be overridden."
        )
    if not header_value or not _safe_latin1_value(header_value):
        raise AuthenticationInputError(
            "Invalid --header value; the supplied value was not displayed."
        )
    return StaticHeader(name=name, _value=header_value)


def _parse_cookie(value: str) -> StaticCookie:
    if "=" not in value:
        raise AuthenticationInputError(
            "Invalid --cookie input; expected 'name=value'. The supplied value was not displayed."
        )
    name, cookie_value = value.split("=", 1)
    name = name.strip()
    cookie_value = cookie_value.strip()
    if not _COOKIE_NAME.fullmatch(name):
        raise AuthenticationInputError(
            "Invalid --cookie name; the supplied value was not displayed."
        )
    if not cookie_value or any(character in cookie_value for character in ";\r\n,"):
        raise AuthenticationInputError(
            "Invalid --cookie value; the supplied value was not displayed."
        )
    if not _safe_latin1_value(cookie_value):
        raise AuthenticationInputError(
            "Invalid --cookie value; the supplied value was not displayed."
        )
    return StaticCookie(name=name, _value=cookie_value)


def _safe_latin1_value(value: str) -> bool:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True


def _header_secrets(header: StaticHeader) -> tuple[str, ...]:
    if header.name.casefold() in {"authorization", "proxy-authorization"}:
        scheme, separator, credential = header.value.partition(" ")
        if separator and scheme.casefold() in {"basic", "bearer"} and credential:
            return header.value, credential
    return (header.value,)
