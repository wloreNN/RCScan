"""Models and interfaces for controlled active GET checks."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from rcscan.findings.models import Priority, Severity
from rcscan.fingerprint.models import Confidence
from rcscan.web.http import WebResponse
from rcscan.web.models import WebDiscoveryResult, WebEndpoint
from rcscan.web_security.models import WebFindingCategory


class ActiveWebCheckContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    discovery: WebDiscoveryResult
    endpoint: WebEndpoint
    parameter: str = Field(min_length=1, max_length=200)


class ActiveWebCheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(pattern=r"^active-web-[a-z0-9-]{3,100}$")
    category: WebFindingCategory
    title: str = Field(min_length=1, max_length=300)
    url: str = Field(min_length=1, max_length=2_048)
    parameter: str = Field(min_length=1, max_length=200)
    evidence: str = Field(min_length=1, max_length=500)
    severity: Severity
    priority: Priority
    confidence: Confidence
    remediation: str = Field(min_length=1, max_length=1_500)
    metadata: dict[str, str] = Field(default_factory=dict)


class ActiveWebSession(Protocol):
    async def get(
        self,
        context: ActiveWebCheckContext,
        *,
        value_suffix: str = "",
        replacement_value: str | None = None,
        raw_encoded: bool = False,
        force: bool = False,
    ) -> WebResponse | None: ...


class ActiveWebCheck(Protocol):
    @property
    def rule_id(self) -> str: ...

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> ActiveWebCheckResult | None: ...
