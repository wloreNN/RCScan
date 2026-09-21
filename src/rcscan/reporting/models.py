"""Versioned canonical models shared by every report exporter."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ReportModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class ReportFeatures(ReportModel):
    fingerprinting: bool
    vulnerability_lookup: bool
    active_verification: bool
    web_discovery: bool
    web_checks: bool
    active_web_checks: bool


class ReportScanMetadata(ReportModel):
    scan_id: str
    status: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    targets: tuple[str, ...]
    authorized_scope: tuple[str, ...]
    selected_ports: tuple[int, ...]
    profile_name: str
    authorization_confirmed: bool
    features: ReportFeatures


class ReportVulnerabilityCandidate(ReportModel):
    advisory_id: str
    source: str
    status: str
    affected_match: str
    environment_applicability: str
    confidence: str
    reason: str
    provenance: str
    references: tuple[str, ...]


class ReportPort(ReportModel):
    port: int
    protocol: str
    state: str
    latency_ms: float
    service: str | None = None
    product: str | None = None
    version: str | None = None
    fingerprint_confidence: str | None = None
    encrypted: bool | None = None
    fingerprint_evidence: tuple[str, ...] = ()
    tls_metadata: dict[str, str] = Field(default_factory=dict)
    vulnerability_candidates: tuple[ReportVulnerabilityCandidate, ...] = ()
    error: str | None = None


class ReportHost(ReportModel):
    target: str
    resolved_address: str | None
    discovery_status: str
    discovery_method: str
    ports: tuple[ReportPort, ...]
    error: str | None = None


class ReportParameter(ReportModel):
    name: str
    source: str
    input_type: str | None = None


class ReportEndpoint(ReportModel):
    url: str
    status_code: int | None
    content_type: str | None
    query_parameters: tuple[ReportParameter, ...]
    truncated: bool
    discovered_via_resource: bool
    response_headers: dict[str, str]
    error: str | None = None


class ReportForm(ReportModel):
    page_url: str
    method: str
    action_url: str
    inputs: tuple[ReportParameter, ...]


class ReportWebDiscovery(ReportModel):
    origin: str
    pages_crawled: int
    endpoints: tuple[ReportEndpoint, ...]
    forms: tuple[ReportForm, ...]
    query_parameter_count: int
    scripts: tuple[str, ...]
    resources: tuple[str, ...]
    errors: tuple[str, ...]


class ReportReproductionEvidence(ReportModel):
    method: str | None = None
    sanitized_url: str | None = None
    parameter: str | None = None
    baseline_status: int | None = None
    probe_status: int | None = None
    response_content_type: str | None = None
    response_length: int | None = None
    rule_id: str | None = None
    confirmation: str | None = None
    summary: str


class ReportFinding(ReportModel):
    finding_id: str
    title: str
    category: str
    finding_type: str
    target: str
    port: int
    service: str
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    severity: str
    priority: str
    confidence: str
    applicability: str
    rule_id: str
    rule_family: str | None = None
    platform: str | None = None
    confirmation: str | None = None
    evidence: tuple[str, ...]
    reproduction: ReportReproductionEvidence
    remediation: str
    references: tuple[str, ...]
    source: str
    provider_provenance: str
    advisory_id: str | None = None
    metadata: dict[str, str]


class ReportSummary(ReportModel):
    hosts: int
    ports: int
    open_ports: int
    vulnerability_candidates: int
    web_origins: int
    findings: int
    findings_by_severity: dict[str, int]


class RCScanReport(ReportModel):
    schema_uri: str = Field(
        default="https://rcscan.local/schemas/report/v1",
        serialization_alias="schema",
    )
    schema_version: str = "1.0"
    report_type: str = "RCSCAN_SCAN_REPORT"
    rcscan_version: str
    generated_at: datetime
    scan: ReportScanMetadata
    summary: ReportSummary
    hosts: tuple[ReportHost, ...]
    web_discovery: tuple[ReportWebDiscovery, ...]
    findings: tuple[ReportFinding, ...]
