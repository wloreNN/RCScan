"""Provider-independent active-verification models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from rcscan.findings.models import FindingType
from rcscan.fingerprint.models import Confidence, Service


class VerificationStatus(StrEnum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class HttpMethod(StrEnum):
    HEAD = "HEAD"
    GET = "GET"
    OPTIONS = "OPTIONS"


class SafetyClassification(StrEnum):
    SYNTHETIC_READ_ONLY = "SYNTHETIC_READ_ONLY"
    PRODUCTION_READ_ONLY_IDENTITY = "PRODUCTION_READ_ONLY_IDENTITY"


class VerificationCheck(StrEnum):
    BODY_MARKER = "BODY_MARKER"
    SERVER_IDENTITY = "SERVER_IDENTITY"


class VerificationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    summary: str = Field(min_length=1, max_length=500)


class VerificationRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,99}$")
    verifier_name: str = Field(min_length=1, max_length=100)
    services: tuple[Service, ...] = Field(min_length=1, max_length=2)
    finding_type: FindingType
    product: str = Field(min_length=1, max_length=128)
    version: str | None = Field(default=None, min_length=1, max_length=128)
    cve_id: str | None = Field(
        default=None,
        pattern=r"^CVE-(?:\d{4}|DEMO)-[A-Z0-9-]+$",
    )
    check: VerificationCheck
    method: HttpMethod
    path: str = Field(min_length=1, max_length=200)
    expected_marker: str | None = Field(default=None, min_length=1, max_length=200)
    requires_observed_version: bool = False
    max_requests: int = Field(ge=1, le=2)
    timeout_seconds: float = Field(gt=0, le=5)
    rationale: str = Field(min_length=1, max_length=500)
    applicability_requirements: str = Field(min_length=1, max_length=500)
    expected_evidence: str = Field(min_length=1, max_length=500)
    result_semantics: str = Field(min_length=1, max_length=500)
    false_positive_limitations: str = Field(min_length=1, max_length=500)
    false_negative_limitations: str = Field(min_length=1, max_length=500)
    safety: SafetyClassification

    @field_validator("path")
    @classmethod
    def validate_safe_path(cls, path: str) -> str:
        try:
            path.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("Verification path must contain only ASCII characters.") from exc
        if (
            not path.startswith("/")
            or any(character.isspace() or ord(character) < 0x21 for character in path)
        ):
            raise ValueError("Verification path must be an absolute safe HTTP path.")
        return path

    @model_validator(mode="after")
    def validate_reviewed_check(self) -> Self:
        if len(set(self.services)) != len(self.services):
            raise ValueError("Verification rule services must be unique.")
        if any(service not in {Service.HTTP, Service.HTTPS} for service in self.services):
            raise ValueError("HTTP verification rules support only HTTP and HTTPS.")
        if self.check is VerificationCheck.BODY_MARKER:
            if self.expected_marker is None:
                raise ValueError("Body-marker rules require an expected marker.")
            if self.requires_observed_version:
                raise ValueError("Body-marker rules cannot use dynamic version matching.")
        elif self.check is VerificationCheck.SERVER_IDENTITY:
            if self.expected_marker is not None:
                raise ValueError("Server-identity rules cannot define a body marker.")
            if not self.requires_observed_version:
                raise ValueError("Server-identity rules require an observed version.")
            if self.version is not None or self.cve_id is not None:
                raise ValueError(
                    "Server-identity rules cannot define an exact version or CVE."
                )
            if self.method is not HttpMethod.HEAD or self.path != "/":
                raise ValueError("Server-identity rules are restricted to HEAD /.")
        return self


class HttpExchange(BaseModel):
    model_config = ConfigDict(frozen=True)

    status_code: int | None = Field(default=None, ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    malformed: bool = False
    error: str | None = Field(default=None, max_length=300)
    duration_ms: float = Field(ge=0)


class VerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(pattern=r"^AF-[0-9a-f]{24}$")
    verification_id: str = Field(pattern=r"^AV-[0-9a-f]{24}$")
    verifier_name: str = Field(min_length=1, max_length=100)
    rule_id: str | None = Field(default=None, max_length=100)
    status: VerificationStatus
    confidence: Confidence
    evidence: tuple[VerificationEvidence, ...] = ()
    reason: str = Field(min_length=1, max_length=500)
    requests_attempted: int = Field(ge=0, le=2)
    duration_ms: float = Field(ge=0)
    generated_at: datetime
