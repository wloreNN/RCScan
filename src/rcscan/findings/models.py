"""Provider-independent finding models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from rcscan.fingerprint.models import Confidence, Service
from rcscan.vuln.models import Applicability, CVSSMetric, LookupProvenance


class FindingType(StrEnum):
    KNOWN_VULNERABILITY = "KNOWN_VULNERABILITY"
    SERVICE_EXPOSURE = "SERVICE_EXPOSURE"
    TLS_CONFIGURATION = "TLS_CONFIGURATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    MISCONFIGURATION = "MISCONFIGURATION"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"


class Priority(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RemediationProvenance(StrEnum):
    PROVIDER = "PROVIDER"
    GENERIC = "GENERIC"


class EvidenceType(StrEnum):
    OBSERVED = "OBSERVED"
    NORMALIZED = "NORMALIZED"
    CORRELATION = "CORRELATION"


class FindingEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: EvidenceType
    summary: str = Field(min_length=1, max_length=500)


class RemediationGuidance(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str = Field(min_length=1, max_length=1_500)
    provenance: RemediationProvenance
    source: str = Field(min_length=1, max_length=200)


class Finding(BaseModel):
    """One potential issue derived from existing bounded scan evidence."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(pattern=r"^AF-[0-9a-f]{24}$")
    title: str = Field(min_length=1, max_length=300)
    type: FindingType
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)
    transport: str = Field(default="TCP", pattern=r"^TCP$")
    service: Service
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=128)
    cve_id: str | None = Field(
        default=None,
        pattern=r"^CVE-(?:\d{4}|DEMO)-[A-Z0-9-]+$",
    )
    description: str = Field(max_length=2_000)
    evidence: tuple[FindingEvidence, ...]
    applicability: Applicability
    confidence: Confidence
    confidence_reason: str = Field(min_length=1, max_length=500)
    cvss: CVSSMetric | None = None
    severity: Severity
    priority: Priority
    remediation: RemediationGuidance
    references: tuple[str, ...] = ()
    source: str = Field(min_length=1, max_length=200)
    provider_provenance: LookupProvenance
    first_observed: datetime
    metadata: dict[str, str] = Field(default_factory=dict)
