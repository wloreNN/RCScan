"""Conservative passive checks over bounded M7 evidence."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from rcscan.findings.models import (
    EvidenceType,
    Finding,
    FindingEvidence,
    FindingType,
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.vuln.models import Applicability, LookupProvenance
from rcscan.web.models import WebDiscoveryResult, WebEndpoint
from rcscan.web_security.models import (
    WebCheck,
    WebCheckContext,
    WebCheckResult,
    WebFindingCategory,
)

_SERVER_VERSION = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}/[A-Za-z0-9._+-]{1,64}")
_SESSION_COOKIE = re.compile(r"(?:session|sess|sid|auth|token|jwt)", re.IGNORECASE)
_VERBOSE_ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "stack trace:",
    "uncaught exception",
    "werkzeug debugger",
    "django technical 500",
    "whoops, looks like something went wrong",
    "system.invalidoperationexception",
)
_DATABASE_ERROR_SIGNATURES = (
    "sqlstate[",
    "mysql_fetch_",
    "postgresql query failed",
    "ora-",
    "sqliteexception",
)
_FILESYSTEM_PATH = re.compile(
    r"(?:[A-Za-z]:\\(?:Users|inetpub|xampp|www)\\|/(?:var/www|home|srv/www)/)"
)
_SENSITIVE_HINT = re.compile(
    r"(?:admin|backup|config|debug|private|secret|staging|internal)",
    re.IGNORECASE,
)
_ARTIFACT_PATH = re.compile(
    r"(?:\.bak|\.backup|\.old|\.orig|\.save|~|\.env|\.map)$",
    re.IGNORECASE,
)
_DEBUG_PATH = re.compile(
    r"(?:^|/)(?:debug|status|server-status|phpinfo|actuator|metrics)(?:/|$)",
    re.IGNORECASE,
)


class MissingHeaderCheck:
    def __init__(
        self,
        *,
        rule_id: str,
        header: str,
        title: str,
        remediation: str,
        https_only: bool = False,
    ) -> None:
        self._rule_id = rule_id
        self._header = header
        self._title = title
        self._remediation = remediation
        self._https_only = https_only

    @property
    def rule_id(self) -> str:
        return self._rule_id

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        discovery = context.discovery
        if self._https_only and urlsplit(discovery.origin).scheme != "https":
            return ()
        endpoint = _representative_html(discovery)
        if endpoint is None or self._header in endpoint.response_headers:
            return ()
        return (
            _result(
                rule_id=self.rule_id,
                category=WebFindingCategory.SECURITY_MISCONFIGURATION,
                title=self._title,
                endpoint=endpoint,
                evidence=f"Response omitted the {self._header} header.",
                severity=Severity.LOW,
                priority=Priority.LOW,
                confidence=Confidence.HIGH,
                remediation=self._remediation,
                scope=discovery.origin,
            ),
        )


class FrameProtectionCheck:
    rule_id = "web-missing-frame-protection"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        endpoint = _representative_html(context.discovery)
        if endpoint is None:
            return ()
        headers = endpoint.response_headers
        csp = headers.get("content-security-policy", "").casefold()
        if "frame-ancestors" in csp or headers.get("x-frame-options"):
            return ()
        return (
            _result(
                rule_id=self.rule_id,
                category=WebFindingCategory.SECURITY_MISCONFIGURATION,
                title="Frame embedding protection not observed",
                endpoint=endpoint,
                evidence=(
                    "Neither CSP frame-ancestors nor X-Frame-Options was observed "
                    "on the representative HTML response."
                ),
                severity=Severity.LOW,
                priority=Priority.LOW,
                confidence=Confidence.HIGH,
                remediation=(
                    "Define CSP frame-ancestors with the required allowlist, or use "
                    "X-Frame-Options where legacy compatibility is needed."
                ),
                scope=context.discovery.origin,
            ),
        )


class CookieSecurityCheck:
    rule_id = "web-cookie-security"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        results: list[WebCheckResult] = []
        https = urlsplit(context.discovery.origin).scheme == "https"
        for endpoint in context.discovery.endpoints:
            for cookie in endpoint.cookies:
                session_like = bool(_SESSION_COOKIE.search(cookie.name))
                if https and session_like and not cookie.secure:
                    results.append(
                        _cookie_result(
                            "web-cookie-secure-missing",
                            "HTTPS session-like cookie lacks Secure",
                            endpoint,
                            cookie.name,
                            "Secure was not present.",
                            Severity.MEDIUM,
                            Priority.MEDIUM,
                            "Add Secure so the cookie is sent only over HTTPS.",
                        )
                    )
                if session_like and not cookie.http_only:
                    results.append(
                        _cookie_result(
                            "web-cookie-httponly-missing",
                            "Session-like cookie lacks HttpOnly",
                            endpoint,
                            cookie.name,
                            "HttpOnly was not present.",
                            Severity.LOW,
                            Priority.LOW,
                            "Add HttpOnly unless client-side script access is explicitly required.",
                        )
                    )
                same_site = (cookie.same_site or "").casefold()
                if session_like and (not same_site or same_site == "none"):
                    results.append(
                        _cookie_result(
                            "web-cookie-samesite-weak",
                            "Session-like cookie has missing or weak SameSite",
                            endpoint,
                            cookie.name,
                            (
                                "SameSite was absent."
                                if not same_site
                                else "SameSite=None was observed."
                            ),
                            Severity.LOW,
                            Priority.LOW,
                            "Use SameSite=Lax or Strict where application flows permit.",
                        )
                    )
        return tuple(results)


class PassiveCorsCheck:
    rule_id = "web-cors-wildcard-credentials"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        for endpoint in context.discovery.endpoints:
            headers = endpoint.response_headers
            if (
                headers.get("access-control-allow-origin", "").strip() == "*"
                and headers.get("access-control-allow-credentials", "").casefold()
                == "true"
            ):
                return (
                    _result(
                        rule_id=self.rule_id,
                        category=WebFindingCategory.CORS_CONFIGURATION,
                        title="Risky passive CORS configuration indicator",
                        endpoint=endpoint,
                        evidence=(
                            "Access-Control-Allow-Origin: * and "
                            "Access-Control-Allow-Credentials: true were both observed."
                        ),
                        severity=Severity.LOW,
                        priority=Priority.LOW,
                        confidence=Confidence.HIGH,
                        remediation=(
                            "Use an explicit reviewed origin allowlist and enable "
                            "credentials only for endpoints that require them."
                        ),
                        scope=context.discovery.origin,
                    ),
                )
        return ()


class ServerVersionDisclosureCheck:
    rule_id = "web-server-version-disclosure"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        for endpoint in context.discovery.endpoints:
            server = endpoint.response_headers.get("server", "")
            if _SERVER_VERSION.match(server):
                return (
                    _result(
                        rule_id=self.rule_id,
                        category=WebFindingCategory.INFORMATION_DISCLOSURE,
                        title="HTTP server product and version disclosed",
                        endpoint=endpoint,
                        evidence=f"Server header explicitly disclosed {server[:150]}.",
                        severity=Severity.INFORMATIONAL,
                        priority=Priority.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                        remediation=(
                            "Suppress unnecessary version detail in externally visible "
                            "server headers where operationally feasible."
                        ),
                        scope=context.discovery.origin,
                    ),
                )
        return ()


class VerboseErrorDisclosureCheck:
    rule_id = "web-verbose-error-disclosure"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        for endpoint in context.discovery.endpoints:
            body = endpoint.body_preview
            lowered = body.casefold()
            indicators = [
                signature
                for signature in (*_VERBOSE_ERROR_SIGNATURES, *_DATABASE_ERROR_SIGNATURES)
                if signature in lowered
            ]
            if indicators or _FILESYSTEM_PATH.search(body):
                evidence = (
                    f"Bounded response contained strong verbose error indicator "
                    f"'{indicators[0]}'."
                    if indicators
                    else "Bounded response disclosed an absolute local filesystem path."
                )
                return (
                    _result(
                        rule_id=self.rule_id,
                        category=WebFindingCategory.INFORMATION_DISCLOSURE,
                        title="Verbose error or debug information disclosed",
                        endpoint=endpoint,
                        evidence=evidence,
                        severity=Severity.MEDIUM,
                        priority=Priority.MEDIUM,
                        confidence=Confidence.HIGH,
                        remediation=(
                            "Disable development error pages and return generic client "
                            "errors while retaining detailed diagnostics only in protected logs."
                        ),
                        scope=context.discovery.origin,
                    ),
                )
        return ()


class ExposedArtifactCheck:
    rule_id = "web-exposed-artifact"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        discovery = context.discovery
        for endpoint in discovery.endpoints:
            path = urlsplit(endpoint.url).path
            if (
                endpoint.status_code is not None
                and 200 <= endpoint.status_code < 300
                and (_ARTIFACT_PATH.search(path) or _DEBUG_PATH.search(path))
            ):
                return (
                    _result(
                        rule_id=self.rule_id,
                        category=WebFindingCategory.INFORMATION_DISCLOSURE,
                        title="Potentially sensitive public artifact discovered",
                        endpoint=endpoint,
                        evidence=(
                            f"Discovered path {path} returned HTTP "
                            f"{endpoint.status_code}; content sensitivity was not inferred."
                        ),
                        severity=Severity.MEDIUM,
                        priority=Priority.MEDIUM,
                        confidence=Confidence.HIGH,
                        remediation=(
                            "Review the artifact and remove it from public routing if "
                            "it is not intentionally exposed."
                        ),
                        scope=path,
                    ),
                )
        for url in (*discovery.resources, *discovery.scripts):
            if _ARTIFACT_PATH.search(urlsplit(url).path):
                endpoint = WebEndpoint(url=url, path=urlsplit(url).path, depth=0)
                return (
                    _result(
                        rule_id=self.rule_id,
                        category=WebFindingCategory.INFORMATION_DISCLOSURE,
                        title="Public artifact reference discovered",
                        endpoint=endpoint,
                        evidence=(
                            "A fetched page explicitly referenced a backup, metadata, "
                            "or source-map-like resource; its contents were not assessed."
                        ),
                        severity=Severity.LOW,
                        priority=Priority.LOW,
                        confidence=Confidence.MEDIUM,
                        remediation="Review and remove unnecessary public artifact references.",
                        scope=endpoint.path,
                    ),
                )
        return ()


class RobotsSitemapHintCheck:
    rule_id = "web-sensitive-discovery-hint"

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]:
        discovery = context.discovery
        candidates = (*discovery.robots_entries, *discovery.sitemap_urls)
        hint = next((value for value in candidates if _SENSITIVE_HINT.search(value)), None)
        if hint is None:
            return ()
        endpoint = WebEndpoint(
            url=f"{discovery.origin}/robots.txt",
            path="/robots.txt",
            depth=0,
        )
        return (
            _result(
                rule_id=self.rule_id,
                category=WebFindingCategory.INFORMATION_DISCLOSURE,
                title="Robots or sitemap exposed an interesting path hint",
                endpoint=endpoint,
                evidence=f"Discovery metadata exposed the bounded hint: {hint[:250]}",
                severity=Severity.INFORMATIONAL,
                priority=Priority.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                remediation=(
                    "Do not rely on robots or sitemap exclusion for access control; "
                    "remove unnecessary sensitive path hints."
                ),
                scope=discovery.origin,
            ),
        )


class WebSecurityEngine:
    def __init__(self, checks: tuple[WebCheck, ...] | None = None) -> None:
        self._checks = checks or default_checks()

    def analyze(
        self,
        discoveries: tuple[WebDiscoveryResult, ...],
    ) -> tuple[Finding, ...]:
        results: list[tuple[WebDiscoveryResult, WebCheckResult]] = []
        seen: set[tuple[str, str, str]] = set()
        for discovery in discoveries:
            context = WebCheckContext(discovery=discovery)
            for check in self._checks:
                try:
                    check_results = check.evaluate(context)
                except Exception:
                    continue
                for result in check_results:
                    key = (result.rule_id, discovery.origin, result.dedup_scope)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append((discovery, result))
        return tuple(_to_finding(discovery, result) for discovery, result in results)


def default_checks() -> tuple[WebCheck, ...]:
    return (
        MissingHeaderCheck(
            rule_id="web-missing-csp",
            header="content-security-policy",
            title="Content-Security-Policy not observed",
            remediation="Define a restrictive, application-tested Content-Security-Policy.",
        ),
        MissingHeaderCheck(
            rule_id="web-missing-hsts",
            header="strict-transport-security",
            title="Strict-Transport-Security not observed",
            remediation="Enable HSTS on HTTPS after confirming complete HTTPS coverage.",
            https_only=True,
        ),
        MissingHeaderCheck(
            rule_id="web-missing-x-content-type-options",
            header="x-content-type-options",
            title="X-Content-Type-Options not observed",
            remediation="Set X-Content-Type-Options: nosniff on applicable responses.",
        ),
        MissingHeaderCheck(
            rule_id="web-missing-referrer-policy",
            header="referrer-policy",
            title="Referrer-Policy not observed",
            remediation="Set an explicit Referrer-Policy appropriate for the application.",
        ),
        FrameProtectionCheck(),
        CookieSecurityCheck(),
        PassiveCorsCheck(),
        ServerVersionDisclosureCheck(),
        VerboseErrorDisclosureCheck(),
        ExposedArtifactCheck(),
        RobotsSitemapHintCheck(),
    )


def _representative_html(discovery: WebDiscoveryResult) -> WebEndpoint | None:
    return next(
        (
            endpoint
            for endpoint in discovery.endpoints
            if endpoint.status_code is not None
            and 200 <= endpoint.status_code < 400
            and (
                endpoint.content_type is None
                or "html" in endpoint.content_type.casefold()
            )
        ),
        None,
    )


def _result(
    *,
    rule_id: str,
    category: WebFindingCategory,
    title: str,
    endpoint: WebEndpoint,
    evidence: str,
    severity: Severity,
    priority: Priority,
    confidence: Confidence,
    remediation: str,
    scope: str,
) -> WebCheckResult:
    return WebCheckResult(
        rule_id=rule_id,
        category=category,
        title=title,
        url=endpoint.url,
        evidence=evidence,
        severity=severity,
        priority=priority,
        confidence=confidence,
        remediation=remediation,
        dedup_scope=scope[:300],
    )


def _cookie_result(
    rule_id: str,
    title: str,
    endpoint: WebEndpoint,
    cookie_name: str,
    detail: str,
    severity: Severity,
    priority: Priority,
    remediation: str,
) -> WebCheckResult:
    return _result(
        rule_id=rule_id,
        category=WebFindingCategory.COOKIE_SECURITY,
        title=title,
        endpoint=endpoint,
        evidence=f"Cookie '{cookie_name}' attributes were observed; {detail}",
        severity=severity,
        priority=priority,
        confidence=Confidence.HIGH,
        remediation=remediation,
        scope=cookie_name.casefold(),
    )


def _to_finding(
    discovery: WebDiscoveryResult,
    result: WebCheckResult,
) -> Finding:
    parsed = urlsplit(result.url)
    service = Service.HTTPS if parsed.scheme == "https" else Service.HTTP
    port = parsed.port or (443 if service is Service.HTTPS else 80)
    finding_type = (
        FindingType.INFORMATION_DISCLOSURE
        if result.category is WebFindingCategory.INFORMATION_DISCLOSURE
        else FindingType.MISCONFIGURATION
    )
    return Finding(
        finding_id=_stable_web_finding_id(
            result.rule_id,
            discovery.origin,
            result.dedup_scope,
        ),
        title=result.title,
        type=finding_type,
        host=parsed.hostname or discovery.origin,
        port=port,
        service=service,
        description=(
            "Passive analysis of bounded M7 response evidence produced this finding. "
            "No exploit payload or parameter mutation was sent."
        ),
        evidence=(
            FindingEvidence(type=EvidenceType.OBSERVED, summary=result.evidence),
        ),
        applicability=Applicability.MATCH,
        confidence=result.confidence,
        confidence_reason=(
            f"{result.confidence.value} confidence based on directly observed, "
            "bounded HTTP metadata or response text."
        ),
        severity=result.severity,
        priority=result.priority,
        remediation=RemediationGuidance(
            text=result.remediation,
            provenance=RemediationProvenance.GENERIC,
            source="RCScan reviewed passive web rule",
        ),
        source=result.rule_id,
        provider_provenance=LookupProvenance.LOCAL_ANALYSIS,
        first_observed=discovery.completed_at,
        metadata={
            "category": result.category.value,
            "affected_url": result.url,
            "rule_id": result.rule_id,
        },
    )


def _stable_web_finding_id(rule_id: str, origin: str, scope: str) -> str:
    identity = "\x1f".join((rule_id.casefold(), origin.casefold(), scope.casefold()))
    return f"AF-{hashlib.sha256(identity.encode()).hexdigest()[:24]}"
