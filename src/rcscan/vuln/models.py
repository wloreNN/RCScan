"""Provider-independent vulnerability intelligence models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from rcscan.fingerprint.models import Confidence


class Applicability(StrEnum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    INDETERMINATE = "INDETERMINATE"


class CandidateStatus(StrEnum):
    POTENTIAL_MATCH = "POTENTIAL_MATCH"


class LookupProvenance(StrEnum):
    LIVE = "LIVE"
    CACHE = "CACHE"
    SYNTHETIC = "SYNTHETIC"
    LOCAL_ANALYSIS = "LOCAL_ANALYSIS"


class NormalizedIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    original_product: str
    vendor: str
    product: str
    version: str
    cpe23: str
    confidence: Confidence
    reason: str

    @property
    def cache_key(self) -> str:
        return f"{self.vendor}|{self.product}|{self.version}"


class CVSSMetric(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    base_score: float = Field(ge=0, le=10)
    base_severity: str | None = None
    vector: str | None = Field(default=None, max_length=300)


class AffectedRange(BaseModel):
    model_config = ConfigDict(frozen=True)

    vendor: str
    product: str
    version: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    vulnerable: bool = True
    conditions_unverified: bool = False


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str = Field(pattern=r"^CVE-(?:\d{4}|DEMO)-[A-Z0-9-]+$")
    source: str
    published: datetime | None = None
    last_modified: datetime | None = None
    description: str = Field(default="No description supplied.", max_length=2_000)
    cvss: tuple[CVSSMetric, ...] = ()
    references: tuple[str, ...] = ()
    affected: tuple[AffectedRange, ...] = ()
    metadata: dict[str, str] = Field(default_factory=dict)


class ProviderQueryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str
    identity_key: str
    records: tuple[VulnerabilityRecord, ...]
    lookup_at: datetime
    provenance: LookupProvenance


class VulnerabilityCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str
    source: str
    status: CandidateStatus = CandidateStatus.POTENTIAL_MATCH
    published: datetime | None = None
    last_modified: datetime | None = None
    description: str
    cvss: CVSSMetric | None = None
    references: tuple[str, ...] = ()
    affected_match: Applicability
    environment_applicability: Applicability
    match_confidence: Confidence
    match_reason: str
    fingerprint_evidence_reference: str
    lookup_at: datetime
    provenance: LookupProvenance
    metadata: dict[str, str] = Field(default_factory=dict)
