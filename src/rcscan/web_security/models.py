"""Provider-independent passive web-security check records."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from rcscan.findings.models import Priority, Severity
from rcscan.fingerprint.models import Confidence
from rcscan.web.models import WebDiscoveryResult


class WebFindingCategory(StrEnum):
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    COOKIE_SECURITY = "COOKIE_SECURITY"
    CORS_CONFIGURATION = "CORS_CONFIGURATION"
    POTENTIAL_SQL_INJECTION = "POTENTIAL_SQL_INJECTION"
    POTENTIAL_REFLECTED_XSS = "POTENTIAL_REFLECTED_XSS"
    POTENTIAL_PATH_TRAVERSAL = "POTENTIAL_PATH_TRAVERSAL"


class WebCheckContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    discovery: WebDiscoveryResult


class WebCheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(pattern=r"^web-[a-z0-9-]{3,100}$")
    category: WebFindingCategory
    title: str = Field(min_length=1, max_length=300)
    url: str = Field(min_length=1, max_length=2_048)
    evidence: str = Field(min_length=1, max_length=500)
    severity: Severity
    priority: Priority
    confidence: Confidence
    remediation: str = Field(min_length=1, max_length=1_500)
    dedup_scope: str = Field(min_length=1, max_length=300)


class WebCheck(Protocol):
    @property
    def rule_id(self) -> str: ...

    def evaluate(self, context: WebCheckContext) -> tuple[WebCheckResult, ...]: ...
