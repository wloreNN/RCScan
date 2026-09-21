"""Conservative HTTP/1.x response parser."""

from __future__ import annotations

import re

from rcscan.fingerprint.evidence import make_evidence, safe_preview
from rcscan.fingerprint.models import (
    Confidence,
    EvidenceSource,
    FingerprintEvidence,
    Service,
    ServiceFingerprint,
)

_STATUS_LINE = re.compile(r"^HTTP/(?P<version>1\.[01]) (?P<status>[1-5][0-9]{2})(?: .*)?$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SERVER_PRODUCT = re.compile(
    r"^(?P<product>[A-Za-z][A-Za-z0-9._-]{0,63})"
    r"(?:/(?P<version>[A-Za-z0-9][A-Za-z0-9._+-]{0,63}))?(?:\s|$)"
)
_SELECTED_HEADERS = {"server", "content-type", "location", "via"}


def parse_http_response(
    data: bytes,
    *,
    probe_used: str,
    encrypted: bool = False,
    prior_evidence: tuple[FingerprintEvidence, ...] = (),
    prior_metadata: dict[str, str] | None = None,
) -> ServiceFingerprint | None:
    """Return HTTP/HTTPS only when a valid status line and header boundary exist."""
    header_block = _extract_header_block(data)
    if header_block is None:
        return None
    lines = header_block.replace(b"\r\n", b"\n").split(b"\n")
    try:
        status_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    status = _STATUS_LINE.fullmatch(status_line)
    if status is None:
        return None

    headers: dict[str, str] = {}
    malformed_headers = False
    for raw_line in lines[1:]:
        if not raw_line:
            continue
        if b":" not in raw_line:
            malformed_headers = True
            continue
        raw_name, raw_value = raw_line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").strip().lower()
        except UnicodeDecodeError:
            malformed_headers = True
            continue
        if not _HEADER_NAME.fullmatch(name):
            malformed_headers = True
            continue
        value = raw_value.decode("iso-8859-1").strip()
        headers.setdefault(name, safe_preview(value.encode("utf-8"), limit=256))

    product: str | None = None
    version: str | None = None
    server = headers.get("server")
    if server is not None:
        server_match = _SERVER_PRODUCT.match(server)
        if server_match is not None:
            product = server_match.group("product")
            version = server_match.group("version")

    metadata = dict(prior_metadata or {})
    metadata.update(
        {
            "http_version": status.group("version"),
            "status_code": status.group("status"),
        }
    )
    metadata.update(
        {
            f"http_{name.replace('-', '_')}": value
            for name, value in headers.items()
            if name in _SELECTED_HEADERS
        }
    )
    if malformed_headers:
        metadata["malformed_headers"] = "true"

    preview_parts = [status_line]
    if server is not None:
        preview_parts.append(f"Server: {server}")
    http_evidence = make_evidence(
        EvidenceSource.HTTP_RESPONSE,
        "Valid HTTP status line and bounded headers received.",
        "\r\n".join(preview_parts).encode("utf-8"),
    )
    return ServiceFingerprint(
        service=Service.HTTPS if encrypted else Service.HTTP,
        product=product,
        version=version,
        confidence=Confidence.MEDIUM if malformed_headers else Confidence.HIGH,
        evidence=(*prior_evidence, http_evidence),
        probe_used=probe_used,
        encrypted=encrypted,
        metadata=metadata,
    )


def _extract_header_block(data: bytes) -> bytes | None:
    for delimiter in (b"\r\n\r\n", b"\n\n"):
        position = data.find(delimiter)
        if position >= 0:
            return data[:position]
    return None
