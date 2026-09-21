"""Small explicit registry of reviewed verification rules."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from time import perf_counter

from rcscan.findings.models import Finding, FindingType
from rcscan.fingerprint.models import Confidence, Service
from rcscan.verification.base import (
    VerificationSession,
    Verifier,
    stable_verification_id,
)
from rcscan.verification.errors import VerificationBudgetExhausted
from rcscan.verification.models import (
    HttpMethod,
    SafetyClassification,
    VerificationCheck,
    VerificationEvidence,
    VerificationResult,
    VerificationRule,
    VerificationStatus,
)

DEMO_RULE = VerificationRule(
    rule_id="rcscan-m6-demo-marker",
    verifier_name="synthetic-http-marker",
    services=(Service.HTTP,),
    finding_type=FindingType.KNOWN_VULNERABILITY,
    product="RCScanDemo",
    version="1.0.0",
    cve_id="CVE-DEMO-M6-0001",
    check=VerificationCheck.BODY_MARKER,
    method=HttpMethod.GET,
    path="/rcscan-demo-status",
    expected_marker="RCSCAN_M6_DEMO_OK",
    max_requests=1,
    timeout_seconds=2.0,
    rationale="Observe one inert marker exposed by the localhost-only synthetic demo.",
    applicability_requirements=(
        "Exact HTTP RCScanDemo 1.0.0 finding with CVE-DEMO-M6-0001."
    ),
    expected_evidence="The exact synthetic marker appears in the bounded response body.",
    result_semantics="Confirms only that the synthetic demonstration marker was observed.",
    false_positive_limitations=(
        "Any responder intentionally copying the synthetic marker can satisfy the rule."
    ),
    false_negative_limitations=(
        "Routing, timeout, truncation, or removal of the marker can prevent confirmation."
    ),
    safety=SafetyClassification.SYNTHETIC_READ_ONLY,
)

_SERVER_PRODUCT = re.compile(
    r"^(?P<product>[A-Za-z][A-Za-z0-9._-]{0,63})"
    r"(?:/(?P<version>[A-Za-z0-9][A-Za-z0-9._+-]{0,63}))?(?:\s|$)"
)


def _identity_rule(rule_id: str, product: str) -> VerificationRule:
    return VerificationRule(
        rule_id=rule_id,
        verifier_name="http-server-identity",
        services=(Service.HTTP, Service.HTTPS),
        finding_type=FindingType.KNOWN_VULNERABILITY,
        product=product,
        check=VerificationCheck.SERVER_IDENTITY,
        method=HttpMethod.HEAD,
        path="/",
        requires_observed_version=True,
        max_requests=1,
        timeout_seconds=2.0,
        rationale=(
            "Send one ordinary HEAD request and compare only the bounded Server header "
            "with the identity already observed by passive fingerprinting."
        ),
        applicability_requirements=(
            f"HTTP or HTTPS KNOWN_VULNERABILITY finding with exact product {product}, "
            "an observed version, and a CVE identity."
        ),
        expected_evidence=(
            f"A valid non-redirect response has a Server token identifying {product} "
            "at the exact version recorded on the finding."
        ),
        result_semantics=(
            "VERIFIED corroborates only the observed service product and version; it "
            "does not verify the CVE, vulnerability presence, or exploitability."
        ),
        false_positive_limitations=(
            "Server headers are operator-controlled and can identify a proxy, be "
            "spoofed, or differ from the software processing the request."
        ),
        false_negative_limitations=(
            "Servers may suppress or rewrite the Server header, and virtual-host, "
            "proxy, routing, timeout, truncation, or redirect behavior can prevent "
            "identity confirmation."
        ),
        safety=SafetyClassification.PRODUCTION_READ_ONLY_IDENTITY,
    )


NGINX_IDENTITY_RULE = _identity_rule(
    "http-server-identity-nginx-v1",
    "nginx",
)
APACHE_IDENTITY_RULE = _identity_rule(
    "http-server-identity-apache-v1",
    "Apache",
)
MICROSOFT_IIS_IDENTITY_RULE = _identity_rule(
    "http-server-identity-microsoft-iis-v1",
    "Microsoft-IIS",
)
PRODUCTION_RULES = (
    NGINX_IDENTITY_RULE,
    APACHE_IDENTITY_RULE,
    MICROSOFT_IIS_IDENTITY_RULE,
)


class HttpMarkerVerifier:
    def __init__(self, rule: VerificationRule) -> None:
        self._rule = rule

    @property
    def name(self) -> str:
        return self._rule.verifier_name

    @property
    def rule_id(self) -> str:
        return self._rule.rule_id

    def supports(self, finding: Finding) -> bool:
        return (
            finding.service in self._rule.services
            and finding.type is self._rule.finding_type
            and finding.product == self._rule.product
            and finding.version == self._rule.version
            and finding.cve_id == self._rule.cve_id
        )

    async def verify(
        self,
        session: VerificationSession,
        finding: Finding,
    ) -> VerificationResult:
        started = perf_counter()
        verification_id = stable_verification_id(
            finding.finding_id,
            self.name,
            self._rule.rule_id,
        )
        try:
            exchange = await session.request(finding, self._rule)
        except VerificationBudgetExhausted:
            return VerificationResult(
                finding_id=finding.finding_id,
                verification_id=verification_id,
                verifier_name=self.name,
                rule_id=self._rule.rule_id,
                status=VerificationStatus.NOT_ATTEMPTED,
                confidence=Confidence.LOW,
                reason="The central verification request budget was unavailable.",
                requests_attempted=0,
                duration_ms=(perf_counter() - started) * 1_000,
                generated_at=datetime.now(UTC),
            )

        status, confidence, reason, evidence = _interpret_exchange(
            exchange,
            self._rule.expected_marker or "",
        )
        return VerificationResult(
            finding_id=finding.finding_id,
            verification_id=verification_id,
            verifier_name=self.name,
            rule_id=self._rule.rule_id,
            status=status,
            confidence=confidence,
            evidence=evidence,
            reason=reason,
            requests_attempted=1,
            duration_ms=(perf_counter() - started) * 1_000,
            generated_at=datetime.now(UTC),
        )


class HttpServerIdentityVerifier:
    def __init__(self, rule: VerificationRule) -> None:
        self._rule = rule

    @property
    def name(self) -> str:
        return self._rule.verifier_name

    @property
    def rule_id(self) -> str:
        return self._rule.rule_id

    def supports(self, finding: Finding) -> bool:
        return (
            finding.service in self._rule.services
            and finding.type is self._rule.finding_type
            and finding.product == self._rule.product
            and finding.version is not None
            and finding.cve_id is not None
        )

    async def verify(
        self,
        session: VerificationSession,
        finding: Finding,
    ) -> VerificationResult:
        started = perf_counter()
        verification_id = stable_verification_id(
            finding.finding_id,
            self.name,
            self._rule.rule_id,
        )
        try:
            exchange = await session.request(finding, self._rule)
        except VerificationBudgetExhausted:
            return VerificationResult(
                finding_id=finding.finding_id,
                verification_id=verification_id,
                verifier_name=self.name,
                rule_id=self._rule.rule_id,
                status=VerificationStatus.NOT_ATTEMPTED,
                confidence=Confidence.LOW,
                reason="The central verification request budget was unavailable.",
                requests_attempted=0,
                duration_ms=(perf_counter() - started) * 1_000,
                generated_at=datetime.now(UTC),
            )

        status, confidence, reason, evidence = _interpret_identity_exchange(
            exchange,
            expected_product=self._rule.product,
            expected_version=finding.version or "",
        )
        return VerificationResult(
            finding_id=finding.finding_id,
            verification_id=verification_id,
            verifier_name=self.name,
            rule_id=self._rule.rule_id,
            status=status,
            confidence=confidence,
            evidence=evidence,
            reason=reason,
            requests_attempted=1,
            duration_ms=(perf_counter() - started) * 1_000,
            generated_at=datetime.now(UTC),
        )


class VerificationRegistry:
    def __init__(self, verifiers: tuple[Verifier, ...]) -> None:
        self._verifiers = verifiers

    def select(self, finding: Finding) -> Verifier | None:
        return next(
            (verifier for verifier in self._verifiers if verifier.supports(finding)),
            None,
        )


def demo_registry() -> VerificationRegistry:
    return VerificationRegistry((HttpMarkerVerifier(DEMO_RULE),))


def production_registry() -> VerificationRegistry:
    return VerificationRegistry(
        tuple(HttpServerIdentityVerifier(rule) for rule in PRODUCTION_RULES)
    )


def default_registry() -> VerificationRegistry:
    """Return the synthetic rule plus the reviewed production-safe rule pack."""
    return VerificationRegistry(
        (
            HttpMarkerVerifier(DEMO_RULE),
            *(HttpServerIdentityVerifier(rule) for rule in PRODUCTION_RULES),
        )
    )


def _interpret_exchange(
    exchange: object,
    marker: str,
) -> tuple[
    VerificationStatus,
    Confidence,
    str,
    tuple[VerificationEvidence, ...],
]:
    from rcscan.verification.models import HttpExchange

    if not isinstance(exchange, HttpExchange):
        raise TypeError("Verifier session returned an invalid HTTP exchange.")
    if exchange.error:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            f"Safe verification could not complete: {exchange.error}",
            (),
        )
    if exchange.truncated:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            "The bounded response limit was reached before verification completed.",
            (),
        )
    if exchange.malformed or exchange.status_code is None:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            "The endpoint returned a malformed HTTP response.",
            (),
        )
    if 300 <= exchange.status_code < 400:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            "The endpoint returned a redirect; verification never follows redirects.",
            (),
        )
    if marker.encode("utf-8") in exchange.body:
        return (
            VerificationStatus.VERIFIED,
            Confidence.HIGH,
            "Expected non-destructive synthetic verification indicator was observed.",
            (
                VerificationEvidence(
                    summary=(
                        f"Received HTTP {exchange.status_code} and the exact reviewed "
                        "synthetic marker."
                    )
                ),
            ),
        )
    return (
        VerificationStatus.NOT_VERIFIED,
        Confidence.MEDIUM,
        "A valid bounded response was received, but the expected indicator was absent.",
        (
            VerificationEvidence(
                summary=f"Received HTTP {exchange.status_code} without the reviewed marker."
            ),
        ),
    )


def _interpret_identity_exchange(
    exchange: object,
    *,
    expected_product: str,
    expected_version: str,
) -> tuple[
    VerificationStatus,
    Confidence,
    str,
    tuple[VerificationEvidence, ...],
]:
    from rcscan.verification.models import HttpExchange

    if not isinstance(exchange, HttpExchange):
        raise TypeError("Verifier session returned an invalid HTTP exchange.")
    if exchange.error:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            f"Safe verification could not complete: {exchange.error}",
            (),
        )
    if exchange.truncated:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            "The bounded response limit was reached before verification completed.",
            (),
        )
    if exchange.malformed or exchange.status_code is None:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            "The endpoint returned a malformed HTTP response.",
            (),
        )
    if 300 <= exchange.status_code < 400:
        return (
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
            "The endpoint returned a redirect; verification never follows redirects.",
            (),
        )

    server = exchange.headers.get("server")
    observed = _SERVER_PRODUCT.match(server) if server is not None else None
    if (
        observed is not None
        and observed.group("product") == expected_product
        and observed.group("version") == expected_version
    ):
        return (
            VerificationStatus.VERIFIED,
            Confidence.HIGH,
            (
                "A bounded Server header strictly reconfirmed the observed product "
                "and version. This does not verify the CVE or exploitability."
            ),
            (
                VerificationEvidence(
                    summary=(
                        f"Received HTTP {exchange.status_code}; Server identified "
                        f"{expected_product}/{expected_version}."
                    )
                ),
            ),
        )

    return (
        VerificationStatus.NOT_VERIFIED,
        Confidence.MEDIUM,
        (
            "A valid bounded response did not strictly reconfirm the finding's "
            "observed Server product and version."
        ),
        (
            VerificationEvidence(
                summary=(
                    f"Received HTTP {exchange.status_code}; the bounded Server header "
                    "was absent or did not exactly match the observed identity."
                )
            ),
        ),
    )
