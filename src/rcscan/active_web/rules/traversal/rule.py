"""Adaptive path-traversal check using reviewed low-sensitivity markers."""

from __future__ import annotations

import logging
from difflib import SequenceMatcher

from rcscan.active_web.models import (
    ActiveWebCheckContext,
    ActiveWebCheckResult,
    ActiveWebSession,
)
from rcscan.active_web.rules.traversal.models import (
    TraversalSignatureMatch,
    TraversalVariant,
)
from rcscan.active_web.rules.traversal.selection import (
    classify_eligibility,
    infer_platform,
    select_variants,
)
from rcscan.active_web.rules.traversal.signatures import (
    match_standard_marker,
)
from rcscan.findings.models import Priority, Severity
from rcscan.fingerprint.models import Confidence
from rcscan.web.http import WebResponse
from rcscan.web_security.models import WebFindingCategory

MAX_TRAVERSAL_REQUESTS_PER_PARAMETER = 6
MAX_INITIAL_PROBES = 2
MAX_ADAPTIVE_VARIANTS = 3
_LOGGER = logging.getLogger(__name__)


class AdaptivePathTraversalCheck:
    rule_id = "active-web-potential-path-traversal"

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> ActiveWebCheckResult | None:
        eligibility = classify_eligibility(context)
        _LOGGER.debug(
            "Traversal eligibility endpoint=%s parameter=%s eligible=%s score=%d "
            "reason=%s",
            context.endpoint.url,
            context.parameter,
            eligibility.eligible,
            eligibility.score,
            "; ".join(eligibility.reasons) or "no file/path evidence",
        )
        if not eligibility.eligible:
            _LOGGER.debug(
                "Traversal skipped endpoint=%s parameter=%s reason=not eligible",
                context.endpoint.url,
                context.parameter,
            )
            return None
        requests = 0
        baseline_length = len(context.endpoint.body_preview.encode("utf-8"))
        if context.endpoint.status_code is None:
            _LOGGER.debug(
                "Traversal baseline request endpoint=%s parameter=%s source=active",
                context.endpoint.url,
                context.parameter,
            )
            baseline_response = await _request_baseline(session, context)
            if baseline_response is None:
                _LOGGER.debug(
                    "Traversal skipped endpoint=%s parameter=%s "
                    "reason=baseline unavailable or budget exhausted",
                    context.endpoint.url,
                    context.parameter,
                )
                return None
            requests = 1
            baseline_length = len(baseline_response.body)
            context = context.model_copy(
                update={
                    "endpoint": context.endpoint.model_copy(
                        update={
                            "status_code": baseline_response.status_code,
                            "content_type": baseline_response.headers.get(
                                "content-type"
                            ),
                            "response_headers": baseline_response.headers,
                            "body_preview": baseline_response.body.decode(
                                "utf-8",
                                errors="replace",
                            )[:16_384],
                        }
                    )
                }
            )
        _LOGGER.debug(
            "Traversal baseline obtained endpoint=%s parameter=%s status=%s "
            "content_type=%s length=%d",
            context.endpoint.url,
            context.parameter,
            context.endpoint.status_code,
            context.endpoint.content_type or "unknown",
            baseline_length,
        )
        baseline_match = match_standard_marker(context.endpoint.body_preview)
        if baseline_match is not None:
            _LOGGER.debug(
                "Traversal baseline marker endpoint=%s parameter=%s marker=%s "
                "classification=matching probe markers will be rejected",
                context.endpoint.url,
                context.parameter,
                baseline_match.marker_id,
            )
        variants = select_variants(context)
        _LOGGER.debug(
            "Traversal rules selected endpoint=%s parameter=%s initial=%s "
            "adaptive=%s",
            context.endpoint.url,
            context.parameter,
            ",".join(
                variant.variant_id for variant in variants if variant.initial
            ),
            ",".join(
                variant.variant_id for variant in variants if not variant.initial
            ),
        )
        attempted: set[str] = set()
        signal_reason: str | None = None

        initial = tuple(variant for variant in variants if variant.initial)[
            :MAX_INITIAL_PROBES
        ]
        for variant in initial:
            response = await _request_variant(session, context, variant)
            if response is None:
                return None
            requests += 1
            attempted.add(variant.variant_id)
            marker = _new_marker(response, baseline_match)
            if marker is not None:
                _LOGGER.debug(
                    "Traversal classification endpoint=%s parameter=%s rule=%s "
                    "result=strong-marker marker=%s",
                    context.endpoint.url,
                    context.parameter,
                    variant.variant_id,
                    marker.marker_id,
                )
                return await _confirm(
                    context=context,
                    session=session,
                    variant=variant,
                    marker=marker,
                    eligibility_score=eligibility.score,
                    eligibility_reasons=eligibility.reasons,
                    requests_used=requests,
                    escalation="Strong marker appeared during initial classification.",
                )
            if signal_reason is None:
                signal_reason = _weak_signal(context, response)
            _LOGGER.debug(
                "Traversal classification endpoint=%s parameter=%s rule=%s "
                "result=%s",
                context.endpoint.url,
                context.parameter,
                variant.variant_id,
                f"weak-signal ({signal_reason})" if signal_reason else "no-signal",
            )

        if signal_reason is None:
            _LOGGER.debug(
                "Traversal stopped endpoint=%s parameter=%s "
                "reason=no meaningful initial signal",
                context.endpoint.url,
                context.parameter,
            )
            return None

        adaptive = tuple(
            variant
            for variant in variants
            if not variant.initial and variant.variant_id not in attempted
        )[:MAX_ADAPTIVE_VARIANTS]
        for variant in adaptive:
            if requests >= MAX_TRAVERSAL_REQUESTS_PER_PARAMETER - 1:
                return None
            response = await _request_variant(session, context, variant)
            if response is None:
                return None
            requests += 1
            marker = _new_marker(response, baseline_match)
            if marker is not None:
                _LOGGER.debug(
                    "Traversal classification endpoint=%s parameter=%s rule=%s "
                    "result=strong-marker marker=%s",
                    context.endpoint.url,
                    context.parameter,
                    variant.variant_id,
                    marker.marker_id,
                )
                return await _confirm(
                    context=context,
                    session=session,
                    variant=variant,
                    marker=marker,
                    eligibility_score=eligibility.score,
                    eligibility_reasons=eligibility.reasons,
                    requests_used=requests,
                    escalation=(
                        f"Initial probes produced a bounded differential "
                        f"({signal_reason}); selected adaptive variants."
                    ),
                )
            _LOGGER.debug(
                "Traversal classification endpoint=%s parameter=%s rule=%s "
                "result=no-strong-marker",
                context.endpoint.url,
                context.parameter,
                variant.variant_id,
            )
        _LOGGER.debug(
            "Traversal stopped endpoint=%s parameter=%s "
            "reason=adaptive variants produced no strong marker",
            context.endpoint.url,
            context.parameter,
        )
        return None


async def _request_variant(
    session: ActiveWebSession,
    context: ActiveWebCheckContext,
    variant: TraversalVariant,
    *,
    force: bool = False,
) -> WebResponse | None:
    _LOGGER.debug(
        "Traversal probe attempted endpoint=%s parameter=%s rule=%s family=%s",
        context.endpoint.url,
        context.parameter,
        variant.variant_id,
        variant.family.value,
    )
    response = await session.get(
        context,
        replacement_value=variant.value,
        raw_encoded=variant.raw_encoded,
        force=force,
    )
    if (
        response is None
        or response.error is not None
        or response.truncated
        or response.status_code is None
        or 300 <= response.status_code < 400
    ):
        _LOGGER.debug(
            "Traversal probe unavailable endpoint=%s parameter=%s rule=%s "
            "reason=transport, redirect, truncation, or budget",
            context.endpoint.url,
            context.parameter,
            variant.variant_id,
        )
        return None
    _LOGGER.debug(
        "Traversal probe response endpoint=%s parameter=%s rule=%s status=%s "
        "content_type=%s length=%d",
        context.endpoint.url,
        context.parameter,
        variant.variant_id,
        response.status_code,
        response.headers.get("content-type", "unknown"),
        len(response.body),
    )
    return response


async def _request_baseline(
    session: ActiveWebSession,
    context: ActiveWebCheckContext,
) -> WebResponse | None:
    response = await session.get(context, value_suffix="")
    if (
        response is None
        or response.error is not None
        or response.truncated
        or response.status_code is None
        or 300 <= response.status_code < 400
    ):
        return None
    return response


def _new_marker(
    response: WebResponse,
    baseline_match: TraversalSignatureMatch | None,
) -> TraversalSignatureMatch | None:
    marker = match_standard_marker(response.body)
    if marker is None:
        return None
    if baseline_match is not None and baseline_match.marker_id == marker.marker_id:
        return None
    return marker


def _weak_signal(
    context: ActiveWebCheckContext,
    response: WebResponse,
) -> str | None:
    baseline_status = context.endpoint.status_code
    if baseline_status != response.status_code:
        return f"HTTP status changed from {baseline_status} to {response.status_code}"
    baseline_type = (context.endpoint.content_type or "").split(";", 1)[0].casefold()
    response_type = response.headers.get("content-type", "").split(";", 1)[0].casefold()
    if baseline_type and response_type and baseline_type != response_type:
        return f"content type changed from {baseline_type} to {response_type}"
    baseline = " ".join(context.endpoint.body_preview[:16_384].casefold().split())
    modified = " ".join(
        response.body.decode("utf-8", errors="replace")[:16_384].casefold().split()
    )
    similarity = SequenceMatcher(None, baseline, modified, autojunk=True).ratio()
    length_delta = abs(len(baseline) - len(modified)) / max(
        len(baseline),
        len(modified),
        1,
    )
    if similarity <= 0.75 and length_delta >= 0.20:
        return (
            f"normalized response similarity was {similarity:.2f} with "
            f"relative length delta {length_delta:.2f}"
        )
    return None


async def _confirm(
    *,
    context: ActiveWebCheckContext,
    session: ActiveWebSession,
    variant: TraversalVariant,
    marker: TraversalSignatureMatch,
    eligibility_score: int,
    eligibility_reasons: tuple[str, ...],
    requests_used: int,
    escalation: str,
) -> ActiveWebCheckResult | None:
    if requests_used >= MAX_TRAVERSAL_REQUESTS_PER_PARAMETER:
        _LOGGER.debug(
            "Traversal confirmation skipped endpoint=%s parameter=%s rule=%s "
            "reason=traversal request cap",
            context.endpoint.url,
            context.parameter,
            variant.variant_id,
        )
        return None
    _LOGGER.debug(
        "Traversal confirmation attempted endpoint=%s parameter=%s rule=%s",
        context.endpoint.url,
        context.parameter,
        variant.variant_id,
    )
    confirmation = await _request_variant(
        session,
        context,
        variant,
        force=True,
    )
    if confirmation is None:
        _LOGGER.debug(
            "Traversal confirmation failed endpoint=%s parameter=%s rule=%s "
            "reason=no bounded response",
            context.endpoint.url,
            context.parameter,
            variant.variant_id,
        )
        return None
    repeated = match_standard_marker(confirmation.body)
    if repeated is None or repeated.marker_id != marker.marker_id:
        _LOGGER.debug(
            "Traversal confirmation failed endpoint=%s parameter=%s rule=%s "
            "reason=marker not reproduced",
            context.endpoint.url,
            context.parameter,
            variant.variant_id,
        )
        return None
    _LOGGER.debug(
        "Traversal confirmation succeeded endpoint=%s parameter=%s rule=%s "
        "result=confirmed-by-repeat",
        context.endpoint.url,
        context.parameter,
        variant.variant_id,
    )
    inferred_platform = infer_platform(context)
    confidence = (
        Confidence.HIGH if eligibility_score >= 3 else Confidence.MEDIUM
    )
    return ActiveWebCheckResult(
        rule_id="active-web-potential-path-traversal",
        category=WebFindingCategory.POTENTIAL_PATH_TRAVERSAL,
        title="Potential Path Traversal / Local File Disclosure",
        url=context.endpoint.url,
        parameter=context.parameter,
        evidence=(
            f"{escalation} Rule {variant.variant_id} "
            f"({variant.family.value}, {variant.platform.value}) produced "
            f"{marker.marker_id}: {marker.reason} The same bounded signature was "
            "reproduced by one confirmation request and was absent from baseline."
        ),
        severity=Severity.MEDIUM,
        priority=Priority.MEDIUM,
        confidence=confidence,
        remediation=(
            "Do not concatenate untrusted input into filesystem paths. Resolve paths "
            "against a fixed allowed base directory, canonicalize before validation, "
            "enforce allowlisted identifiers where practical, and reject resolution "
            "outside the intended directory."
        ),
        metadata={
            "rule_family": variant.variant_id,
            "platform": marker.platform.value,
            "confirmation_status": "CONFIRMED_BY_REPEAT",
            "traversal_family": variant.family.value,
            "traversal_variant": variant.variant_id,
            "marker_id": marker.marker_id,
            "marker_platform": marker.platform.value,
            "inferred_platform": inferred_platform.value,
            "eligibility_score": str(eligibility_score),
            "eligibility_reason": "; ".join(eligibility_reasons)[:300],
            "confirmation": "REPEATED",
        },
    )
