"""Budgeted asynchronous execution of explicitly supported verification rules."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import UTC, datetime
from time import perf_counter

from rcscan.findings.models import Finding
from rcscan.fingerprint.models import Confidence
from rcscan.verification.base import stable_verification_id
from rcscan.verification.errors import VerificationBudgetExhausted
from rcscan.verification.http import VerificationHttpClient
from rcscan.verification.models import (
    HttpExchange,
    VerificationResult,
    VerificationRule,
    VerificationStatus,
)
from rcscan.verification.registry import VerificationRegistry, default_registry


class RequestBudget:
    def __init__(self, *, per_finding: int, total: int) -> None:
        self._per_finding = per_finding
        self._total = total
        self._used_total = 0
        self._used_by_finding: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def reserve(self, finding_id: str, rule_limit: int) -> bool:
        async with self._lock:
            finding_limit = min(self._per_finding, rule_limit)
            if (
                self._used_total >= self._total
                or self._used_by_finding[finding_id] >= finding_limit
            ):
                return False
            self._used_total += 1
            self._used_by_finding[finding_id] += 1
            return True

    def used_for(self, finding_id: str) -> int:
        return self._used_by_finding[finding_id]


class _BudgetedSession:
    def __init__(
        self,
        client: VerificationHttpClient,
        budget: RequestBudget,
    ) -> None:
        self._client = client
        self._budget = budget

    async def request(
        self,
        finding: Finding,
        rule: VerificationRule,
    ) -> HttpExchange:
        if not await self._budget.reserve(finding.finding_id, rule.max_requests):
            raise VerificationBudgetExhausted
        return await self._client.request(finding, rule)

    def attempts(self, finding_id: str) -> int:
        return self._budget.used_for(finding_id)


class VerificationEngine:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        max_requests_per_finding: int,
        max_total_requests: int,
        concurrency: int,
        registry: VerificationRegistry | None = None,
        client: VerificationHttpClient | None = None,
    ) -> None:
        self._registry = registry or default_registry()
        self._client = client or VerificationHttpClient(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        self._max_requests_per_finding = max_requests_per_finding
        self._max_total_requests = max_total_requests
        self._concurrency = concurrency
        self._logger = logging.getLogger(__name__)

    async def verify(
        self,
        findings: tuple[Finding, ...],
    ) -> tuple[VerificationResult, ...]:
        if not findings:
            return ()
        queue: asyncio.Queue[int] = asyncio.Queue()
        for index in range(len(findings)):
            queue.put_nowait(index)
        results: list[VerificationResult | None] = [None] * len(findings)
        budget = RequestBudget(
            per_finding=self._max_requests_per_finding,
            total=self._max_total_requests,
        )
        session = _BudgetedSession(self._client, budget)

        async def worker() -> None:
            while True:
                try:
                    index = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                finding = findings[index]
                verifier = None
                try:
                    verifier = self._registry.select(finding)
                    if verifier is None:
                        result = _skipped_result(finding)
                    else:
                        result = await verifier.verify(session, finding)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    verifier_name = verifier.name if verifier is not None else "registry"
                    rule_id = verifier.rule_id if verifier is not None else "selection-error"
                    result = VerificationResult(
                        finding_id=finding.finding_id,
                        verification_id=stable_verification_id(
                            finding.finding_id,
                            verifier_name,
                            rule_id,
                        ),
                        verifier_name=verifier_name,
                        rule_id=rule_id,
                        status=VerificationStatus.ERROR,
                        confidence=Confidence.LOW,
                        reason="The verifier encountered an unexpected isolated error.",
                        requests_attempted=session.attempts(finding.finding_id),
                        duration_ms=0,
                        generated_at=datetime.now(UTC),
                    )
                    self._logger.debug(
                        "Verifier failed finding_id=%s verifier=%s",
                        finding.finding_id,
                        verifier_name,
                        exc_info=True,
                    )
                results[index] = result
                queue.task_done()

        started = perf_counter()
        async with asyncio.TaskGroup() as group:
            for _ in range(min(self._concurrency, len(findings))):
                group.create_task(worker())
        self._logger.debug(
            "Active verification completed findings=%d requests=%d duration_ms=%.2f",
            len(findings),
            sum(item.requests_attempted for item in results if item is not None),
            (perf_counter() - started) * 1_000,
        )
        return tuple(item for item in results if item is not None)


def _skipped_result(finding: Finding) -> VerificationResult:
    return VerificationResult(
        finding_id=finding.finding_id,
        verification_id=stable_verification_id(
            finding.finding_id,
            "registry",
            "unsupported",
        ),
        verifier_name="registry",
        status=VerificationStatus.SKIPPED,
        confidence=Confidence.LOW,
        reason="No explicitly reviewed verification rule supports this finding.",
        requests_attempted=0,
        duration_ms=0,
        generated_at=datetime.now(UTC),
    )
