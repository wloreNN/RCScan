"""Verifier and budgeted-session abstractions."""

from __future__ import annotations

import hashlib
from typing import Protocol

from rcscan.findings.models import Finding
from rcscan.verification.models import (
    HttpExchange,
    VerificationResult,
    VerificationRule,
)


class VerificationSession(Protocol):
    async def request(
        self,
        finding: Finding,
        rule: VerificationRule,
    ) -> HttpExchange: ...


class Verifier(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def rule_id(self) -> str: ...

    def supports(self, finding: Finding) -> bool: ...

    async def verify(
        self,
        session: VerificationSession,
        finding: Finding,
    ) -> VerificationResult: ...


def stable_verification_id(finding_id: str, verifier_name: str, rule_id: str) -> str:
    identity = "\x1f".join(
        (finding_id.casefold(), verifier_name.casefold(), rule_id.casefold())
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"AV-{digest}"
