"""Convert existing scan evidence into one canonical report model."""

from __future__ import annotations

from collections import Counter

from rcscan import __version__
from rcscan.findings.models import Finding
from rcscan.models.scan import Scan
from rcscan.network.models import PortResult, ScanRunResult
from rcscan.reporting.models import (
    RCScanReport,
    ReportEndpoint,
    ReportFeatures,
    ReportFinding,
    ReportForm,
    ReportHost,
    ReportParameter,
    ReportPort,
    ReportReproductionEvidence,
    ReportScanMetadata,
    ReportSummary,
    ReportVulnerabilityCandidate,
    ReportWebDiscovery,
)
from rcscan.reporting.sanitizer import sanitize_mapping, sanitize_text, sanitize_url
from rcscan.verification.models import VerificationResult
from rcscan.web.models import WebParameter

__all__ = ["ReportFeatures", "build_report"]


def build_report(
    scan: Scan,
    result: ScanRunResult,
    *,
    features: ReportFeatures,
) -> RCScanReport:
    findings = _all_findings(result)
    report_findings = tuple(
        _finding(item, result.verification_results)
        for item in sorted(findings, key=lambda finding: finding.finding_id)
    )
    hosts = tuple(_host(host) for host in result.hosts)
    web = tuple(
        ReportWebDiscovery(
            origin=sanitize_url(discovery.origin),
            pages_crawled=discovery.pages_crawled,
            endpoints=tuple(_endpoint(item) for item in discovery.endpoints),
            forms=tuple(_form(item) for item in discovery.forms),
            query_parameter_count=discovery.query_parameter_count,
            scripts=tuple(sanitize_url(item) for item in discovery.scripts),
            resources=tuple(sanitize_url(item) for item in discovery.resources),
            errors=tuple(sanitize_text(item) for item in discovery.errors),
        )
        for discovery in result.web_discovery_results
    )
    severity_counts = Counter(finding.severity for finding in report_findings)
    return RCScanReport(
        rcscan_version=__version__,
        generated_at=result.completed_at,
        scan=ReportScanMetadata(
            scan_id=str(result.scan_id),
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            duration_seconds=result.duration_seconds,
            targets=tuple(target.value for target in scan.targets),
            authorized_scope=tuple(target.value for target in scan.authorized_scope),
            selected_ports=scan.ports,
            profile_name=scan.profile_name,
            authorization_confirmed=scan.authorization_confirmed,
            features=features,
        ),
        summary=ReportSummary(
            hosts=len(hosts),
            ports=sum(len(host.ports) for host in hosts),
            open_ports=result.open_ports,
            vulnerability_candidates=sum(
                len(port.vulnerability_candidates)
                for host in result.hosts
                for port in host.ports
            ),
            web_origins=len(web),
            findings=len(report_findings),
            findings_by_severity=dict(sorted(severity_counts.items())),
        ),
        hosts=hosts,
        web_discovery=web,
        findings=report_findings,
    )


def _all_findings(result: ScanRunResult) -> tuple[Finding, ...]:
    unique: dict[str, Finding] = {}
    for finding in (
        *result.findings,
        *result.web_findings,
        *result.active_web_findings,
    ):
        unique.setdefault(finding.finding_id, finding)
    return tuple(unique.values())


def _host(host: object) -> ReportHost:
    from rcscan.network.models import HostScanResult

    assert isinstance(host, HostScanResult)
    return ReportHost(
        target=sanitize_text(host.target),
        resolved_address=host.resolved_address,
        discovery_status=host.discovery_status.value,
        discovery_method=host.discovery_method.value,
        ports=tuple(_port(port) for port in host.ports),
        error=sanitize_text(host.error) if host.error else None,
    )


def _port(port: PortResult) -> ReportPort:
    fingerprint = port.fingerprint
    candidates = tuple(
        ReportVulnerabilityCandidate(
            advisory_id=candidate.cve_id,
            source=sanitize_text(candidate.source),
            status=candidate.status.value,
            affected_match=candidate.affected_match.value,
            environment_applicability=candidate.environment_applicability.value,
            confidence=candidate.match_confidence.value,
            reason=sanitize_text(candidate.match_reason),
            provenance=candidate.provenance.value,
            references=tuple(sanitize_url(item) for item in candidate.references),
        )
        for candidate in port.vulnerability_candidates
    )
    return ReportPort(
        port=port.port,
        protocol=port.protocol.value,
        state=port.state.value,
        latency_ms=port.latency_ms,
        service=fingerprint.service.value if fingerprint else None,
        product=sanitize_text(fingerprint.product) if fingerprint and fingerprint.product else None,
        version=sanitize_text(fingerprint.version) if fingerprint and fingerprint.version else None,
        fingerprint_confidence=fingerprint.confidence.value if fingerprint else None,
        encrypted=fingerprint.encrypted if fingerprint else None,
        fingerprint_evidence=(
            tuple(sanitize_text(item.summary) for item in fingerprint.evidence)
            if fingerprint
            else ()
        ),
        tls_metadata=(
            sanitize_mapping(fingerprint.metadata)
            if fingerprint and fingerprint.encrypted
            else {}
        ),
        vulnerability_candidates=candidates,
        error=sanitize_text(port.error_message) if port.error_message else None,
    )


def _parameter(parameter: WebParameter) -> ReportParameter:
    return ReportParameter(
        name=sanitize_text(parameter.name),
        source=parameter.source.value,
        input_type=sanitize_text(parameter.input_type) if parameter.input_type else None,
    )


def _endpoint(endpoint: object) -> ReportEndpoint:
    from rcscan.web.models import WebEndpoint

    assert isinstance(endpoint, WebEndpoint)
    return ReportEndpoint(
        url=sanitize_url(endpoint.url),
        status_code=endpoint.status_code,
        content_type=sanitize_text(endpoint.content_type) if endpoint.content_type else None,
        query_parameters=tuple(_parameter(item) for item in endpoint.query_parameters),
        truncated=endpoint.truncated,
        discovered_via_resource=endpoint.discovered_via_resource,
        response_headers=sanitize_mapping(endpoint.response_headers),
        error=sanitize_text(endpoint.error) if endpoint.error else None,
    )


def _form(form: object) -> ReportForm:
    from rcscan.web.models import WebForm

    assert isinstance(form, WebForm)
    return ReportForm(
        page_url=sanitize_url(form.page_url),
        method=form.method,
        action_url=sanitize_url(form.action_url),
        inputs=tuple(_parameter(item) for item in form.inputs),
    )


def _finding(
    finding: Finding,
    verification_results: tuple[VerificationResult, ...],
) -> ReportFinding:
    metadata = sanitize_mapping(finding.metadata)
    url = metadata.get("affected_url")
    rule_id = metadata.get("rule_id", finding.source)
    confirmation = metadata.get("confirmation_status") or metadata.get("confirmation")
    verification = next(
        (
            item
            for item in verification_results
            if item.finding_id == finding.finding_id
        ),
        None,
    )
    if confirmation is None and verification is not None:
        confirmation = verification.status.value
    evidence = tuple(sanitize_text(item.summary) for item in finding.evidence)
    method = metadata.get("http_method") or metadata.get("method")
    if method is None and finding.source.startswith("active-web-"):
        method = "GET"
    reproduction = ReportReproductionEvidence(
        method=method,
        sanitized_url=sanitize_url(url) if url else None,
        parameter=metadata.get("parameter"),
        baseline_status=_metadata_int(metadata, "baseline_status"),
        probe_status=_metadata_int(metadata, "probe_status"),
        response_content_type=metadata.get("response_content_type"),
        response_length=_metadata_int(metadata, "response_length"),
        rule_id=rule_id,
        confirmation=confirmation,
        summary=evidence[0] if evidence else sanitize_text(finding.description),
    )
    return ReportFinding(
        finding_id=finding.finding_id,
        title=sanitize_text(finding.title),
        category=metadata.get("category", finding.type.value),
        finding_type=finding.type.value,
        target=sanitize_text(finding.host),
        port=finding.port,
        service=finding.service.value,
        url=sanitize_url(url) if url else None,
        http_method=method,
        parameter=metadata.get("parameter"),
        severity=finding.severity.value,
        priority=finding.priority.value,
        confidence=finding.confidence.value,
        applicability=finding.applicability.value,
        rule_id=rule_id,
        rule_family=metadata.get("rule_family"),
        platform=metadata.get("platform"),
        confirmation=confirmation,
        evidence=evidence,
        reproduction=reproduction,
        remediation=sanitize_text(finding.remediation.text),
        references=tuple(sanitize_url(item) for item in finding.references),
        source=sanitize_text(finding.source),
        provider_provenance=finding.provider_provenance.value,
        advisory_id=finding.cve_id,
        metadata=metadata,
    )


def _metadata_int(metadata: dict[str, str], name: str) -> int | None:
    value = metadata.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
