from datetime import UTC

import pytest

from rcscan.fingerprint.evidence import make_evidence, safe_preview
from rcscan.fingerprint.models import Confidence, EvidenceSource, Service
from rcscan.fingerprint.parsers.http import parse_http_response
from rcscan.fingerprint.parsers.ssh import parse_ssh_banner


def test_safe_preview_is_bounded_after_control_escaping() -> None:
    preview = safe_preview(b"A\r\n\t\x1b\x00B", limit=13)

    assert preview == r"A\r\n\t\x1b"
    assert len(preview) <= 13
    assert "\r" not in preview
    assert "\n" not in preview
    assert "\x1b" not in preview


def test_safe_preview_replaces_invalid_utf8_and_honors_tiny_limit() -> None:
    assert safe_preview(b"\xffABC", limit=2) == "\ufffdA"
    assert safe_preview(b"\n", limit=1) == ""


def test_make_evidence_uses_utc_and_omits_empty_raw_preview() -> None:
    evidence = make_evidence(EvidenceSource.OBSERVATION, "bounded", b"")

    assert evidence.raw_preview is None
    assert evidence.timestamp.tzinfo is UTC


def test_ssh_valid_generic_banner_preserves_protocol_and_software() -> None:
    result = parse_ssh_banner(b"notice\r\nSSH-2.0-dropbear_2024.86 comment\r\n")

    assert result is not None
    assert result.service is Service.SSH
    assert result.product is None
    assert result.version is None
    assert result.metadata == {
        "protocol_version": "2.0",
        "software": "dropbear_2024.86",
    }
    assert result.evidence[0].raw_preview == "SSH-2.0-dropbear_2024.86 comment"


@pytest.mark.parametrize(
    ("banner", "version"),
    [
        (b"SSH-2.0-OpenSSH_9.8\r\n", "9.8"),
        (b"SSH-1.99-OpenSSH_7.4p1\n", "7.4p1"),
    ],
)
def test_ssh_extracts_openssh_product_and_version(
    banner: bytes, version: str
) -> None:
    result = parse_ssh_banner(banner)

    assert result is not None
    assert result.product == "OpenSSH"
    assert result.version == version
    assert result.confidence is Confidence.HIGH
    assert result.probe_used == "Passive banner"


@pytest.mark.parametrize(
    "banner",
    [
        b"SSH-3.0-OpenSSH_9.8\r\n",
        b"SSH-2.0-\r\n",
        b" SSH-2.0-OpenSSH_9.8\r\n",
        b"SSH-2.0-bad\x00software\r\n",
        b"\xffSSH-2.0-OpenSSH_9.8\r\n",
        b"line\n" * 10 + b"SSH-2.0-OpenSSH_9.8\n",
        b"SSH-2.0-" + b"A" * 246 + b"\r\n",
    ],
)
def test_ssh_rejects_malformed_invalid_or_oversized_banners(banner: bytes) -> None:
    assert parse_ssh_banner(banner) is None


@pytest.mark.parametrize(
    ("wire_version", "status"),
    [("1.0", "200"), ("1.1", "404")],
)
def test_http_parses_versions_status_headers_and_server(
    wire_version: str, status: str
) -> None:
    response = (
        f"HTTP/{wire_version} {status} Result\r\n"
        "Server: nginx/1.27.1\r\n"
        "Content-Type: text/plain\r\n"
        "Location: /next\r\n"
        "Via: proxy\r\n"
        "X-Ignored: value\r\n\r\nbody"
    ).encode()

    result = parse_http_response(response, probe_used="HTTP HEAD")

    assert result is not None
    assert result.service is Service.HTTP
    assert result.product == "nginx"
    assert result.version == "1.27.1"
    assert result.metadata == {
        "http_version": wire_version,
        "status_code": status,
        "http_server": "nginx/1.27.1",
        "http_content_type": "text/plain",
        "http_location": "/next",
        "http_via": "proxy",
    }
    assert result.evidence[-1].raw_preview == (
        f"HTTP/{wire_version} {status} Result\\r\\nServer: nginx/1.27.1"
    )


def test_http_without_server_has_no_product_or_version() -> None:
    result = parse_http_response(b"HTTP/1.1 204 No Content\r\nDate: now\r\n\r\n", probe_used="GET")

    assert result is not None
    assert result.product is None
    assert result.version is None
    assert "http_server" not in result.metadata


def test_http_server_product_without_version() -> None:
    result = parse_http_response(b"HTTP/1.1 200 OK\r\nServer: Caddy\r\n\r\n", probe_used="HEAD")

    assert result is not None
    assert result.product == "Caddy"
    assert result.version is None


def test_http_malformed_header_is_retained_as_lower_confidence_evidence() -> None:
    result = parse_http_response(
        b"HTTP/1.1 200 OK\r\nBroken\r\nServer: Apache/2.4.62\r\n\r\n",
        probe_used="HTTP HEAD",
    )

    assert result is not None
    assert result.confidence is Confidence.MEDIUM
    assert result.metadata["malformed_headers"] == "true"
    assert result.product == "Apache"


@pytest.mark.parametrize(
    "response",
    [
        b"",
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\n",
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 999 Weird\r\n\r\n",
        b"\xffHTTP/1.1 200 OK\r\n\r\n",
        b"not http\r\n\r\n",
    ],
)
def test_http_rejects_partial_or_malformed_responses(response: bytes) -> None:
    assert parse_http_response(response, probe_used="HTTP HEAD") is None


def test_http_huge_response_only_exposes_bounded_selected_evidence() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\nX-Huge: "
        + b"A" * 50_000
        + b"\r\n\r\n"
    )

    result = parse_http_response(response, probe_used="HTTP GET")

    assert result is not None
    assert result.product == "nginx"
    assert len(result.evidence[-1].raw_preview or "") < 512
    assert "x_huge" not in result.metadata


def test_https_parser_preserves_tls_evidence_and_metadata() -> None:
    tls_evidence = make_evidence(EvidenceSource.TLS_HANDSHAKE, "TLS succeeded.")

    result = parse_http_response(
        b"HTTP/1.1 200 OK\nServer: envoy/1.2\n\n",
        probe_used="HTTPS HEAD",
        encrypted=True,
        prior_evidence=(tls_evidence,),
        prior_metadata={"tls_version": "TLSv1.3"},
    )

    assert result is not None
    assert result.service is Service.HTTPS
    assert result.encrypted is True
    assert result.evidence[0] is tls_evidence
    assert result.metadata["tls_version"] == "TLSv1.3"
