"""Conservative dotted-numeric version comparison and range matching."""

from __future__ import annotations

import re
from dataclasses import dataclass

from rcscan.vuln.models import AffectedRange, Applicability, NormalizedIdentity

_DOTTED_NUMERIC = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")


@dataclass(frozen=True, slots=True)
class ParsedVersion:
    parts: tuple[int, ...]


def parse_version(value: str) -> ParsedVersion | None:
    if not _DOTTED_NUMERIC.fullmatch(value):
        return None
    return ParsedVersion(tuple(int(part) for part in value.split(".")))


def compare_versions(left: str, right: str) -> int | None:
    """Return -1/0/1, or None when either version is not safely comparable."""
    parsed_left = parse_version(left)
    parsed_right = parse_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    width = max(len(parsed_left.parts), len(parsed_right.parts))
    normalized_left = parsed_left.parts + (0,) * (width - len(parsed_left.parts))
    normalized_right = parsed_right.parts + (0,) * (width - len(parsed_right.parts))
    return (normalized_left > normalized_right) - (normalized_left < normalized_right)


def match_affected_range(
    identity: NormalizedIdentity,
    affected: AffectedRange,
) -> Applicability:
    if not affected.vulnerable:
        return Applicability.NO_MATCH
    if identity.vendor != affected.vendor or identity.product != affected.product:
        return Applicability.NO_MATCH

    exact_version = affected.version
    if exact_version is not None and exact_version not in ("", "*", "-"):
        comparison = compare_versions(identity.version, exact_version)
        if comparison is None:
            return Applicability.INDETERMINATE
        if comparison != 0:
            return Applicability.NO_MATCH

    checks = (
        (affected.version_start_including, -1, False),
        (affected.version_start_excluding, -1, True),
        (affected.version_end_including, 1, False),
        (affected.version_end_excluding, 1, True),
    )
    for boundary, failing_direction, exclusive in checks:
        if boundary is None:
            continue
        comparison = compare_versions(identity.version, boundary)
        if comparison is None:
            return Applicability.INDETERMINATE
        if comparison == failing_direction or (exclusive and comparison == 0):
            return Applicability.NO_MATCH
    return Applicability.MATCH
