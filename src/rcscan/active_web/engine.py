"""Central-budgeted, same-origin active GET checks."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from collections import defaultdict
from collections.abc import Iterator
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from rcscan.active_web.models import (
    ActiveWebCheck,
    ActiveWebCheckContext,
    ActiveWebCheckResult,
    ActiveWebSession,
)
from rcscan.active_web.rules.traversal.rule import (
    AdaptivePathTraversalCheck,
)
from rcscan.findings.models import (
    EvidenceType,
    Finding,
    FindingEvidence,
    FindingType,
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.vuln.models import Applicability, LookupProvenance
from rcscan.web.http import WebHttpClient, WebResponse
from rcscan.web.models import (
    ParameterSource,
    WebDiscoveryResult,
    WebEndpoint,
    WebParameter,
)
from rcscan.web.request_context import WebRequestContext
from rcscan.web.throttle import OriginThrottleCoordinator
from rcscan.web_security.models import WebFindingCategory

_DATABASE_ERRORS = (
    "sqlstate[",
    "you have an error in your sql syntax",
    "unterminated quoted string",
    "unclosed quotation mark after the character string",
    "postgresql query failed",
    "sqliteexception",
    "ora-01756",
    "pdoexception",
)
_LOGGER = logging.getLogger(__name__)


class ActiveRequestBudget:
    def __init__(self, *, per_parameter: int, total: int) -> None:
        self._per_parameter = per_parameter
        self._total = total
        self._used_total = 0
        self._used_by_parameter: defaultdict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def reserve(self, key: str) -> bool:
        async with self._lock:
            if (
                self._used_total >= self._total
                or self._used_by_parameter[key] >= self._per_parameter
            ):
                return False
            self._used_total += 1
            self._used_by_parameter[key] += 1
            return True


class _BudgetedSession:
    def __init__(
        self,
        *,
        client: WebHttpClient,
        budget: ActiveRequestBudget,
        concurrency: int,
    ) -> None:
        self._client = client
        self._budget = budget
        self._semaphore = asyncio.Semaphore(concurrency)
        self._cache: dict[
            tuple[str, str, str, bool],
            WebResponse | None,
        ] = {}

    async def get(
        self,
        context: ActiveWebCheckContext,
        *,
        value_suffix: str = "",
        replacement_value: str | None = None,
        raw_encoded: bool = False,
        force: bool = False,
    ) -> WebResponse | None:
        mutated = _mutate_one_parameter(
            context.endpoint.url,
            context.parameter,
            value_suffix,
            replacement_value=replacement_value,
            raw_encoded=raw_encoded,
        )
        if mutated is None or not _same_origin(mutated, context.discovery.origin):
            return None
        key = (
            f"{context.discovery.origin.casefold()}\x1f"
            f"{urlsplit(context.endpoint.url).path}\x1f"
            f"{context.parameter.casefold()}"
        )
        cache_value = replacement_value if replacement_value is not None else value_suffix
        cache_key = (
            context.endpoint.url,
            context.parameter,
            cache_value,
            raw_encoded,
        )
        if not force and cache_key in self._cache:
            return self._cache[cache_key]
        if not await self._budget.reserve(key):
            self._cache[cache_key] = None
            return None
        connect_host = (
            context.discovery.connect_host
            or urlsplit(context.discovery.origin).hostname
            or ""
        )
        async with self._semaphore:
            if isinstance(self._client, WebHttpClient):
                response = await self._client.get(
                    mutated,
                    connect_host=connect_host,
                    retry_reserver=lambda: self._budget.reserve(key),
                )
            else:
                response = await self._client.get(mutated, connect_host=connect_host)
        _LOGGER.debug(
            "Active-web response endpoint=%s parameter=%s status=%s "
            "content_type=%s network_body_bytes=%d retained_body_bytes=%d "
            "truncated=%s",
            context.endpoint.url,
            context.parameter,
            response.status_code,
            response.headers.get("content-type", "unknown"),
            max(response.bytes_received, len(response.body)),
            len(response.body),
            response.truncated,
        )
        self._cache[cache_key] = response
        return response


class SqlInjectionIndicatorCheck:
    rule_id = "active-web-potential-sql-injection"

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> ActiveWebCheckResult | None:
        shared_probe = _reflection_marker(context)
        modified = await session.get(context, value_suffix=shared_probe)
        if (
            modified is None
            or modified.error
            or modified.truncated
            or modified.status_code is None
        ):
            return None
        if 300 <= modified.status_code < 400:
            return None
        baseline = context.endpoint
        baseline_text = baseline.body_preview.casefold()
        modified_text = modified.body.decode("utf-8", errors="replace").casefold()
        signature = next(
            (
                item
                for item in _DATABASE_ERRORS
                if item in modified_text and item not in baseline_text
            ),
            None,
        )
        if signature is not None:
            return ActiveWebCheckResult(
                rule_id=self.rule_id,
                category=WebFindingCategory.POTENTIAL_SQL_INJECTION,
                title="Potential SQL injection indicator",
                url=context.endpoint.url,
                parameter=context.parameter,
                evidence=(
                    f"Baseline HTTP {baseline.status_code} length "
                    f"{len(baseline.body_preview)}; modified HTTP "
                    f"{modified.status_code} length {len(modified.body)}; "
                    f"new database/parser signature '{signature}' was observed."
                ),
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                confidence=Confidence.HIGH,
                remediation=(
                    "Use parameterized queries or prepared statements and avoid "
                    "including database parser details in HTTP responses."
                ),
            )

        true_suffix, false_suffix = _boolean_suffixes(context)
        true_response = await session.get(context, value_suffix=true_suffix)
        false_response = await session.get(context, value_suffix=false_suffix)
        false_confirmation = await session.get(context, value_suffix=false_suffix + " ")
        if not all(
            _usable_boolean_response(response)
            for response in (true_response, false_response, false_confirmation)
        ):
            return None
        assert true_response is not None
        assert false_response is not None
        assert false_confirmation is not None
        differential = _boolean_differential(
            baseline_status=baseline.status_code,
            baseline_body=baseline.body_preview,
            true_response=true_response,
            false_response=false_response,
            false_confirmation=false_confirmation,
        )
        if differential is None:
            return None
        return ActiveWebCheckResult(
            rule_id=self.rule_id,
            category=WebFindingCategory.POTENTIAL_SQL_INJECTION,
            title="Potential boolean-differential SQL injection indicator",
            url=context.endpoint.url,
            parameter=context.parameter,
            evidence=differential,
            severity=Severity.MEDIUM,
            priority=Priority.MEDIUM,
            confidence=Confidence.MEDIUM,
            remediation=(
                "Use parameterized queries or prepared statements and keep query "
                "syntax separate from untrusted input."
            ),
        )


class ReflectedXssIndicatorCheck:
    rule_id = "active-web-potential-reflected-xss"

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> ActiveWebCheckResult | None:
        marker = _reflection_marker(context)
        modified = await session.get(context, value_suffix=marker)
        if (
            modified is None
            or modified.error
            or modified.truncated
            or modified.status_code is None
        ):
            return None
        if 300 <= modified.status_code < 400:
            return None
        content_type = modified.headers.get("content-type", "").casefold()
        if "html" not in content_type:
            return None
        text = modified.body.decode("utf-8", errors="replace")
        if marker not in text:
            return None
        return ActiveWebCheckResult(
            rule_id=self.rule_id,
            category=WebFindingCategory.POTENTIAL_REFLECTED_XSS,
            title="Potential reflected XSS indicator",
            url=context.endpoint.url,
            parameter=context.parameter,
            evidence=(
                "A unique inert marker containing angle brackets and quotes was "
                "reflected byte-for-byte in an HTML response, indicating those "
                "characters were not output-encoded. No JavaScript was executed."
            ),
            severity=Severity.MEDIUM,
            priority=Priority.MEDIUM,
            confidence=Confidence.MEDIUM,
            remediation=(
                "Apply contextual output encoding and use safe templating APIs for "
                "all untrusted values rendered into HTML."
            ),
        )


class ActiveWebSecurityEngine:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        max_requests_per_parameter: int,
        max_total_requests: int,
        concurrency: int,
        checks: tuple[ActiveWebCheck, ...] | None = None,
        request_context: WebRequestContext | None = None,
        throttle: OriginThrottleCoordinator | None = None,
        client: WebHttpClient | None = None,
    ) -> None:
        self._checks = checks or (
            AdaptivePathTraversalCheck(),
            ReflectedXssIndicatorCheck(),
            SqlInjectionIndicatorCheck(),
        )
        self._request_context = request_context or WebRequestContext()
        self._client = client or WebHttpClient(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            retain_body_for_all_content_types=True,
            request_context=self._request_context,
            throttle=throttle,
        )
        self._max_requests_per_parameter = max_requests_per_parameter
        self._max_total_requests = max_total_requests
        self._concurrency = concurrency

    async def analyze(
        self,
        discoveries: tuple[WebDiscoveryResult, ...],
    ) -> tuple[Finding, ...]:
        for discovery in discoveries:
            self._request_context.register_origin(discovery.origin)
            if isinstance(self._client, WebHttpClient):
                self._client.register_origin(discovery.origin)
        contexts = tuple(_contexts(discoveries))
        if not contexts:
            _LOGGER.debug("Active-web processing found no eligible parameter contexts.")
            return ()
        for context in contexts:
            _LOGGER.debug(
                "Active-web candidate endpoint=%s parameter=%s "
                "resource_reference=%s",
                context.endpoint.url,
                context.parameter,
                context.endpoint.discovered_via_resource,
            )
        session = _BudgetedSession(
            client=self._client,
            budget=ActiveRequestBudget(
                per_parameter=self._max_requests_per_parameter,
                total=self._max_total_requests,
            ),
            concurrency=self._concurrency,
        )

        async def run_context(
            context: ActiveWebCheckContext,
        ) -> tuple[ActiveWebCheckResult, ...]:
            results: list[ActiveWebCheckResult] = []
            for check in self._checks:
                try:
                    result = await check.evaluate(context, session)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    _LOGGER.debug(
                        "Active-web rule failed endpoint=%s parameter=%s rule=%s",
                        context.endpoint.url,
                        context.parameter,
                        check.rule_id,
                        exc_info=True,
                    )
                    continue
                if result is not None:
                    results.append(result)
            return tuple(results)

        tasks = [asyncio.create_task(run_context(context)) for context in contexts]
        try:
            grouped = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        seen: set[tuple[str, str, str, str]] = set()
        findings: list[Finding] = []
        for context, results in zip(contexts, grouped, strict=True):
            for result in results:
                key = (
                    result.rule_id,
                    context.discovery.origin,
                    urlsplit(result.url).path or "/",
                    result.parameter.casefold(),
                )
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_to_finding(context.discovery, result))
        return tuple(findings)


def _contexts(
    discoveries: tuple[WebDiscoveryResult, ...],
) -> Iterator[ActiveWebCheckContext]:
    for discovery in discoveries:
        query_targets: set[tuple[str, str, int, str, str]] = set()
        for endpoint in discovery.endpoints:
            skip_reason: str | None = None
            if (
                endpoint.status_code is None
                and not endpoint.discovered_via_resource
            ):
                skip_reason = "unfetched non-resource endpoint"
            elif endpoint.error is not None:
                skip_reason = "discovery transport error"
            elif endpoint.truncated:
                skip_reason = "truncated discovery response"
            elif not _same_origin(endpoint.url, discovery.origin):
                skip_reason = "different origin"
            if skip_reason is not None:
                for parameter in endpoint.query_parameters:
                    _LOGGER.debug(
                        "Active-web candidate rejected endpoint=%s parameter=%s "
                        "reason=%s",
                        endpoint.url,
                        parameter.name,
                        skip_reason,
                    )
                continue
            for parameter in endpoint.query_parameters:
                key = _target_key(endpoint.url, parameter.name)
                query_targets.add(key)
                yield ActiveWebCheckContext(
                    discovery=discovery,
                    endpoint=endpoint,
                    parameter=parameter.name,
                )
        seen_form_targets: set[tuple[str, str, int, str, str]] = set()
        for form in discovery.forms:
            if form.method != "GET" or not _same_origin(
                form.action_url,
                discovery.origin,
            ):
                continue
            inputs = tuple(
                parameter
                for parameter in form.inputs
                if _testable_form_parameter(parameter)
            )
            if not inputs:
                continue
            baseline = _form_baseline(discovery, form.action_url)
            if baseline is None:
                continue
            form_url = _form_target_url(form.action_url, inputs)
            parsed = urlsplit(form_url)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            form_endpoint = baseline.model_copy(
                update={
                    "url": form_url,
                    "path": path,
                    "query_parameters": tuple(
                        WebParameter(
                            name=parameter.name,
                            source=ParameterSource.FORM,
                            input_type=parameter.input_type,
                        )
                        for parameter in inputs
                    ),
                }
            )
            for parameter in form_endpoint.query_parameters:
                key = _target_key(form_endpoint.url, parameter.name)
                if key in query_targets or key in seen_form_targets:
                    continue
                seen_form_targets.add(key)
                yield ActiveWebCheckContext(
                    discovery=discovery,
                    endpoint=form_endpoint,
                    parameter=parameter.name,
                )


def _testable_form_parameter(parameter: WebParameter) -> bool:
    return (parameter.input_type or "text").casefold() in {
        "email",
        "number",
        "password",
        "search",
        "select",
        "tel",
        "text",
        "textarea",
        "url",
    }


def _form_baseline(
    discovery: WebDiscoveryResult,
    action_url: str,
) -> WebEndpoint | None:
    action = urlsplit(action_url)
    action_pairs = set(parse_qsl(action.query, keep_blank_values=True))
    return next(
        (
            endpoint
            for endpoint in discovery.endpoints
            if endpoint.status_code is not None
            and endpoint.error is None
            and not endpoint.truncated
            and _same_origin(endpoint.url, discovery.origin)
            and urlsplit(endpoint.url).path == action.path
            and action_pairs.issubset(
                set(parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True))
            )
        ),
        None,
    )


def _form_target_url(
    action_url: str,
    inputs: tuple[WebParameter, ...],
) -> str:
    parsed = urlsplit(action_url)
    pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
    existing = {name for name, _value in pairs}
    pairs.extend(
        (parameter.name, "")
        for parameter in inputs
        if parameter.name not in existing
    )
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(pairs), "")
    )


def _target_key(url: str, parameter: str) -> tuple[str, str, int, str, str]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    return (
        scheme,
        (parsed.hostname or "").casefold(),
        parsed.port or (443 if scheme == "https" else 80),
        parsed.path or "/",
        parameter.casefold(),
    )


def _mutate_one_parameter(
    url: str,
    parameter: str,
    suffix: str,
    *,
    replacement_value: str | None = None,
    raw_encoded: bool = False,
) -> str | None:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    mutated = False
    output: list[tuple[str, str]] = []
    target_index: int | None = None
    for name, value in pairs:
        if name == parameter and not mutated:
            output.append(
                (
                    name,
                    replacement_value
                    if replacement_value is not None
                    else value + suffix,
                )
            )
            target_index = len(output) - 1
            mutated = True
        else:
            output.append((name, value))
    if not mutated:
        return None
    if raw_encoded and target_index is not None:
        query = "&".join(
            f"{quote_plus(name)}="
            + (value if index == target_index else quote_plus(value))
            for index, (name, value) in enumerate(output)
        )
    else:
        query = urlencode(output)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _same_origin(url: str, origin: str) -> bool:
    candidate = urlsplit(url)
    expected = urlsplit(origin)
    return (
        candidate.scheme.casefold(),
        (candidate.hostname or "").casefold(),
        candidate.port or (443 if candidate.scheme.casefold() == "https" else 80),
    ) == (
        expected.scheme.casefold(),
        (expected.hostname or "").casefold(),
        expected.port or (443 if expected.scheme.casefold() == "https" else 80),
    )


def _boolean_suffixes(
    context: ActiveWebCheckContext,
) -> tuple[str, str]:
    values = parse_qsl(urlsplit(context.endpoint.url).query, keep_blank_values=True)
    current = next(
        (value for name, value in values if name == context.parameter),
        "",
    )
    if current.strip().lstrip("-").isdigit():
        return " AND 1=1", " AND 1=2"
    return "' AND '1'='1", "' AND '1'='2"


def _usable_boolean_response(response: WebResponse | None) -> bool:
    return (
        response is not None
        and response.error is None
        and not response.truncated
        and response.status_code is not None
        and not 300 <= response.status_code < 400
    )


def _boolean_differential(
    *,
    baseline_status: int | None,
    baseline_body: str,
    true_response: WebResponse,
    false_response: WebResponse,
    false_confirmation: WebResponse,
) -> str | None:
    baseline = _response_profile(baseline_status, baseline_body)
    true = _response_profile(
        true_response.status_code,
        true_response.body.decode("utf-8", errors="replace"),
    )
    false = _response_profile(
        false_response.status_code,
        false_response.body.decode("utf-8", errors="replace"),
    )
    confirmation = _response_profile(
        false_confirmation.status_code,
        false_confirmation.body.decode("utf-8", errors="replace"),
    )
    baseline_true_similarity = _similarity(baseline[1], true[1])
    false_confirmation_similarity = _similarity(false[1], confirmation[1])
    baseline_false_similarity = _similarity(baseline[1], false[1])
    baseline_true_equivalent = (
        baseline[0] == true[0]
        and baseline_true_similarity >= 0.95
        and _relative_length_delta(baseline[1], true[1]) <= 0.08
        and baseline[2] == true[2]
    )
    false_confirmation_stable = (
        false[0] == confirmation[0]
        and false_confirmation_similarity >= 0.95
        and _relative_length_delta(false[1], confirmation[1]) <= 0.08
        and false[2] == confirmation[2]
    )
    marker_difference = len(baseline[3] ^ false[3]) >= 2
    false_materially_differs = baseline[0] != false[0] or (
        baseline_false_similarity <= 0.85
        and (
            _relative_length_delta(baseline[1], false[1]) >= 0.10
            or baseline[2] != false[2]
            or marker_difference
        )
    )
    if not (
        baseline_true_equivalent
        and false_confirmation_stable
        and false_materially_differs
    ):
        return None
    return (
        f"Baseline and TRUE responses were equivalent "
        f"(HTTP {baseline[0]}/{true[0]}, similarity "
        f"{baseline_true_similarity:.2f}); FALSE differed "
        f"(HTTP {false[0]}, similarity {baseline_false_similarity:.2f}, "
        f"lengths {len(baseline[1])}/{len(false[1])}) and a repeated FALSE "
        f"response was stable (similarity {false_confirmation_similarity:.2f})."
    )


def _response_profile(
    status: int | None,
    body: str,
) -> tuple[int | None, str, tuple[str, ...], frozenset[str]]:
    bounded = body[:16_384].casefold()
    bounded = re.sub(r"\b[0-9a-f]{12,}\b", "<token>", bounded)
    bounded = re.sub(r"\b\d{4,}\b", "<number>", bounded)
    normalized = " ".join(bounded.split())
    tags = tuple(re.findall(r"</?[a-z][a-z0-9:-]*", normalized)[:2_000])
    words = frozenset(re.findall(r"\b[a-z][a-z0-9_-]{4,}\b", normalized))
    return status, normalized, tags, words


def _similarity(first: str, second: str) -> float:
    return SequenceMatcher(None, first, second, autojunk=True).ratio()


def _relative_length_delta(first: str, second: str) -> float:
    return abs(len(first) - len(second)) / max(len(first), len(second), 1)


def _reflection_marker(context: ActiveWebCheckContext) -> str:
    identity = f"{context.endpoint.url}\x1f{context.parameter}".encode()
    token = hashlib.sha256(identity).hexdigest()[:10]
    return f"RCSCAN8B_{token}<probe>\"'"


def _to_finding(
    discovery: WebDiscoveryResult,
    result: ActiveWebCheckResult,
) -> Finding:
    parsed = urlsplit(result.url)
    service = Service.HTTPS if parsed.scheme == "https" else Service.HTTP
    port = parsed.port or (443 if service is Service.HTTPS else 80)
    identity = "\x1f".join(
        (
            result.rule_id,
            discovery.origin.casefold(),
            parsed.path,
            result.parameter.casefold(),
        )
    )
    finding_id = f"AF-{hashlib.sha256(identity.encode()).hexdigest()[:24]}"
    return Finding(
        finding_id=finding_id,
        title=result.title,
        type=FindingType.MISCONFIGURATION,
        host=parsed.hostname or discovery.origin,
        port=port,
        service=service,
        description=(
            "A bounded active GET check produced a conservative potential "
            "vulnerability indicator. No exploitation or data extraction occurred."
        ),
        evidence=(
            FindingEvidence(type=EvidenceType.OBSERVED, summary=result.evidence),
        ),
        applicability=Applicability.INDETERMINATE,
        confidence=result.confidence,
        confidence_reason=(
            f"{result.confidence.value} confidence from a bounded baseline and "
            "single-parameter modified GET comparison."
        ),
        severity=result.severity,
        priority=result.priority,
        remediation=RemediationGuidance(
            text=result.remediation,
            provenance=RemediationProvenance.GENERIC,
            source="RCScan controlled active web rule",
        ),
        source=result.rule_id,
        provider_provenance=LookupProvenance.LOCAL_ANALYSIS,
        first_observed=discovery.completed_at,
        metadata={
            "category": result.category.value,
            "affected_url": result.url,
            "parameter": result.parameter,
            "rule_id": result.rule_id,
            **result.metadata,
        },
    )
