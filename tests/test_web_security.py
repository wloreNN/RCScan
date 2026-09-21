from datetime import UTC, datetime

import pytest

from rcscan.web.http import _parse_headers
from rcscan.web.models import WebCookie, WebDiscoveryResult, WebEndpoint
from rcscan.web_security.engine import (
    ServerVersionDisclosureCheck,
    WebSecurityEngine,
)

NOW = datetime(2026, 1, 2, tzinfo=UTC)
SAFE_HEADERS = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def endpoint(
    *,
    url: str = "https://site.example/",
    headers: dict[str, str] | None = None,
    cookies: tuple[WebCookie, ...] = (),
    body: str = "",
    status: int = 200,
) -> WebEndpoint:
    values = dict(SAFE_HEADERS if headers is None else headers)
    return WebEndpoint(
        url=url,
        path="/" + url.split("/", 3)[-1] if url.count("/") >= 3 else "/",
        depth=0,
        status_code=status,
        content_type="text/html",
        response_headers=values,
        cookies=cookies,
        body_preview=body,
    )


def discovery(
    *endpoints: WebEndpoint,
    origin: str = "https://site.example",
    robots: tuple[str, ...] = (),
    sitemap: tuple[str, ...] = (),
    resources: tuple[str, ...] = (),
) -> WebDiscoveryResult:
    return WebDiscoveryResult(
        origin=origin,
        pages_crawled=len(endpoints),
        endpoints=endpoints,
        robots_entries=robots,
        sitemap_urls=sitemap,
        resources=resources,
        started_at=NOW,
        completed_at=NOW,
    )


def sources(result: WebDiscoveryResult) -> set[str]:
    return {finding.source for finding in WebSecurityEngine().analyze((result,))}


@pytest.mark.parametrize(
    ("header", "rule_id"),
    [
        ("content-security-policy", "web-missing-csp"),
        ("x-content-type-options", "web-missing-x-content-type-options"),
        ("referrer-policy", "web-missing-referrer-policy"),
    ],
)
def test_missing_security_headers(header: str, rule_id: str) -> None:
    headers = dict(SAFE_HEADERS)
    headers.pop(header)
    assert rule_id in sources(discovery(endpoint(headers=headers)))


def test_hsts_is_relevant_only_to_https() -> None:
    headers = dict(SAFE_HEADERS)
    headers.pop("strict-transport-security")
    assert "web-missing-hsts" in sources(discovery(endpoint(headers=headers)))
    http_endpoint = endpoint(url="http://site.example/", headers=headers)
    assert "web-missing-hsts" not in sources(
        discovery(http_endpoint, origin="http://site.example")
    )


@pytest.mark.parametrize(
    "headers",
    [
        SAFE_HEADERS,
        {
            **SAFE_HEADERS,
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        },
    ],
)
def test_frame_protection_accepts_csp_or_x_frame_options(
    headers: dict[str, str],
) -> None:
    assert "web-missing-frame-protection" not in sources(
        discovery(endpoint(headers=headers))
    )


def test_missing_frame_protection_is_reported_once_across_pages() -> None:
    headers = {**SAFE_HEADERS, "content-security-policy": "default-src 'self'"}
    findings = WebSecurityEngine().analyze(
        (
            discovery(
                endpoint(headers=headers),
                endpoint(url="https://site.example/two", headers=headers),
            ),
        )
    )
    assert sum(item.source == "web-missing-frame-protection" for item in findings) == 1


def test_https_session_cookie_checks_and_value_redaction() -> None:
    cookie = WebCookie(name="sessionid", secure=False, http_only=False)
    findings = WebSecurityEngine().analyze(
        (discovery(endpoint(cookies=(cookie,))),)
    )
    cookie_sources = {item.source for item in findings if "cookie" in item.source}
    assert cookie_sources == {
        "web-cookie-secure-missing",
        "web-cookie-httponly-missing",
        "web-cookie-samesite-weak",
    }
    assert all("super-secret" not in repr(item) for item in findings)

    status, _headers, cookies = _parse_headers(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=super-secret; Path=/\r\n"
    )
    assert status == 200
    assert cookies[0].name == "sessionid"
    assert "super-secret" not in repr(cookies)


def test_secure_cookie_attributes_suppress_cookie_findings() -> None:
    cookie = WebCookie(
        name="sessionid",
        secure=True,
        http_only=True,
        same_site="Lax",
    )
    assert not {
        source for source in sources(discovery(endpoint(cookies=(cookie,)))) if "cookie" in source
    }


def test_passive_cors_safe_and_risky_cases() -> None:
    safe = endpoint(
        headers={**SAFE_HEADERS, "access-control-allow-origin": "*"}
    )
    risky = endpoint(
        headers={
            **SAFE_HEADERS,
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
    )
    assert "web-cors-wildcard-credentials" not in sources(discovery(safe))
    assert "web-cors-wildcard-credentials" in sources(discovery(risky))


def test_server_version_disclosure_is_informational() -> None:
    findings = WebSecurityEngine().analyze(
        (
            discovery(
                endpoint(headers={**SAFE_HEADERS, "server": "DemoServer/1.2.3"})
            ),
        )
    )
    finding = next(item for item in findings if item.source == "web-server-version-disclosure")
    assert finding.severity.value == "INFORMATIONAL"
    assert finding.cvss is None
    assert finding.cve_id is None


@pytest.mark.parametrize(
    "body",
    [
        "Traceback (most recent call last):\nValueError: synthetic",
        r"Template failed at C:\Users\demo\app\views.py",
        "SQLSTATE[42000] synthetic database detail",
    ],
)
def test_verbose_error_stack_path_and_database_details(body: str) -> None:
    assert "web-verbose-error-disclosure" in sources(
        discovery(endpoint(body=body))
    )


def test_exposed_discovered_artifact_requires_observed_success() -> None:
    exposed = endpoint(url="https://site.example/config.env", status=200)
    missing = endpoint(url="https://site.example/backup.bak", status=404)
    findings = WebSecurityEngine().analyze((discovery(exposed, missing),))
    matches = [item for item in findings if item.source == "web-exposed-artifact"]
    assert len(matches) == 1
    assert matches[0].metadata["affected_url"].endswith("config.env")


def test_source_map_reference_and_sensitive_robots_hint() -> None:
    result = discovery(
        endpoint(),
        resources=("https://site.example/static/app.js.map",),
        robots=("Disallow: /private-admin",),
    )
    found = sources(result)
    assert "web-exposed-artifact" in found
    assert "web-sensitive-discovery-hint" in found


def test_malformed_or_empty_headers_do_not_break_other_checks() -> None:
    findings = WebSecurityEngine().analyze((discovery(endpoint(headers={})),))
    assert findings


class RaisingCheck:
    rule_id = "web-raising-test"

    def evaluate(self, _context: object):
        raise RuntimeError("isolated")


def test_rule_failure_is_isolated() -> None:
    engine = WebSecurityEngine(
        checks=(RaisingCheck(), ServerVersionDisclosureCheck())  # type: ignore[arg-type]
    )
    findings = engine.analyze(
        (
            discovery(
                endpoint(headers={**SAFE_HEADERS, "server": "DemoServer/1.2.3"})
            ),
        )
    )
    assert [item.source for item in findings] == ["web-server-version-disclosure"]
