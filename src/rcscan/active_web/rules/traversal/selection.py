"""Evidence-based traversal eligibility and platform-aware ordering."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from rcscan.active_web.models import ActiveWebCheckContext
from rcscan.active_web.rules.traversal.models import (
    TraversalEligibility,
    TraversalPlatform,
    TraversalVariant,
)
from rcscan.active_web.rules.traversal.registry import (
    reviewed_traversal_variants,
)

_EXACT_PATH_NAMES = {
    "asset",
    "attachment",
    "dir",
    "doc",
    "document",
    "download",
    "file",
    "filename",
    "filepath",
    "folder",
    "image",
    "include",
    "page",
    "path",
    "report",
    "resource",
    "template",
    "view",
}
_PATH_NAME_PARTS = ("file", "path", "template", "download", "document", "attachment")
_FILE_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,8}(?:$|[?#])")
_WINDOWS_EVIDENCE = ("microsoft-iis", "iis", "windows", "asp.net")
_UNIX_EVIDENCE = ("nginx", "apache", "caddy", "gunicorn", "uwsgi")


def classify_eligibility(context: ActiveWebCheckContext) -> TraversalEligibility:
    name = context.parameter.strip().casefold()
    value = _parameter_value(context)
    reasons: list[str] = []
    score = 0
    if name in _EXACT_PATH_NAMES:
        score += 3
        reasons.append("parameter name has reviewed file/path semantics")
    elif any(part in name for part in _PATH_NAME_PARTS):
        score += 2
        reasons.append("parameter name contains a file/path semantic token")
    if "/" in value or "\\" in value:
        score += 2
        reasons.append("existing value contains a path separator")
    if _FILE_EXTENSION.search(value):
        score += 2
        reasons.append("existing value resembles a filename with an extension")
    if value.startswith((".", "~")):
        score += 1
        reasons.append("existing value begins with a relative-path token")
    return TraversalEligibility(
        eligible=score >= 2,
        score=score,
        reasons=tuple(reasons),
    )


def infer_platform(context: ActiveWebCheckContext) -> TraversalPlatform:
    endpoint_evidence = context.endpoint.response_headers.get("server", "").casefold()
    value = _parameter_value(context)
    if any(marker in endpoint_evidence for marker in _WINDOWS_EVIDENCE):
        return TraversalPlatform.WINDOWS
    if re.match(r"^[A-Za-z]:\\", value) or "\\" in value:
        return TraversalPlatform.WINDOWS
    if any(marker in endpoint_evidence for marker in _UNIX_EVIDENCE):
        return TraversalPlatform.UNIX
    if value.startswith("/") or "/" in value:
        return TraversalPlatform.UNIX
    origin_evidence = " ".join(
        endpoint.response_headers.get("server", "")
        for endpoint in context.discovery.endpoints
    ).casefold()
    if any(marker in origin_evidence for marker in _WINDOWS_EVIDENCE):
        return TraversalPlatform.WINDOWS
    if any(marker in origin_evidence for marker in _UNIX_EVIDENCE):
        return TraversalPlatform.UNIX
    return TraversalPlatform.UNKNOWN


def select_variants(
    context: ActiveWebCheckContext,
) -> tuple[TraversalVariant, ...]:
    platform = infer_platform(context)
    variants = reviewed_traversal_variants()
    initial = [variant for variant in variants if variant.initial]
    adaptive = [variant for variant in variants if not variant.initial]
    return tuple(
        [
            *_platform_order(initial, platform),
            *_platform_order(adaptive, platform),
        ]
    )


def _platform_order(
    variants: list[TraversalVariant],
    platform: TraversalPlatform,
) -> list[TraversalVariant]:
    if platform is TraversalPlatform.UNKNOWN:
        preferred = (TraversalPlatform.UNIX, TraversalPlatform.WINDOWS)
    else:
        other = (
            TraversalPlatform.WINDOWS
            if platform is TraversalPlatform.UNIX
            else TraversalPlatform.UNIX
        )
        preferred = (platform, other)
    return [
        variant
        for selected_platform in preferred
        for variant in variants
        if variant.platform is selected_platform
    ]


def _parameter_value(context: ActiveWebCheckContext) -> str:
    return next(
        (
            value
            for name, value in parse_qsl(
                urlsplit(context.endpoint.url).query,
                keep_blank_values=True,
            )
            if name == context.parameter
        ),
        "",
    )
