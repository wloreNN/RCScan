"""Evidence-first service fingerprint models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Service(StrEnum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    TLS = "TLS"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceSource(StrEnum):
    SERVER_BANNER = "server_banner"
    HTTP_RESPONSE = "http_response"
    TLS_HANDSHAKE = "tls_handshake"
    OBSERVATION = "observation"


class FingerprintEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: EvidenceSource
    summary: str = Field(max_length=500)
    raw_preview: str | None = Field(default=None, max_length=512)
    timestamp: datetime


class ServiceFingerprint(BaseModel):
    """A conservative identity supported by bounded response evidence."""

    model_config = ConfigDict(frozen=True)

    service: Service
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=128)
    confidence: Confidence
    evidence: tuple[FingerprintEvidence, ...]
    probe_used: str = Field(max_length=100)
    encrypted: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=500)
