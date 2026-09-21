"""Target and target-file parsing without DNS or network access."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from rcscan.core.exceptions import TargetValidationError
from rcscan.scope.models import Target, TargetType

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_BYTES_PER_ENTRY = 1_024


def parse_target(raw_value: str) -> Target:
    """Parse and normalize an IPv4 address, IPv4 CIDR, or hostname."""
    value = raw_value.strip()
    if not value:
        raise TargetValidationError("Target cannot be empty.")
    if value != raw_value:
        raise TargetValidationError("Target must not contain leading or trailing whitespace.")
    if any(character.isspace() for character in value):
        raise TargetValidationError("Target must not contain whitespace.")
    if "://" in value:
        raise TargetValidationError("URLs are not targets; provide only an IP, CIDR, or hostname.")
    if ":" in value:
        raise TargetValidationError("IPv6 and targets containing ports are not supported.")
    if "/" in value:
        return _parse_network(value)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if value.replace(".", "").isdigit():
            raise TargetValidationError(f"Invalid IPv4 address: {value}") from None
        return _parse_hostname(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise TargetValidationError("IPv6 targets are not supported.")
    return Target(value=str(address), type=TargetType.IP)


def _parse_network(value: str) -> Target:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise TargetValidationError(f"Invalid IPv4 CIDR: {value} ({exc})") from None
    if not isinstance(network, ipaddress.IPv4Network):
        raise TargetValidationError("IPv6 networks are not supported.")
    return Target(value=str(network), type=TargetType.NETWORK)


def _parse_hostname(value: str) -> Target:
    normalized = value.lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized:
        raise TargetValidationError("Hostname cannot be empty.")
    if len(normalized) > 253:
        raise TargetValidationError("Hostname exceeds 253 characters.")
    if "/" in normalized or "\\" in normalized:
        raise TargetValidationError("Targets containing paths are not supported.")
    labels = normalized.split(".")
    if any(not label or not _HOST_LABEL.fullmatch(label) for label in labels):
        raise TargetValidationError(f"Malformed hostname: {value}")
    return Target(value=normalized, type=TargetType.HOSTNAME)


def parse_target_file(path: Path, max_targets: int) -> tuple[Target, ...]:
    """Read, validate, and deduplicate one UTF-8 target per line."""
    try:
        if path.stat().st_size > max_targets * _MAX_BYTES_PER_ENTRY:
            raise TargetValidationError(
                f"Target file exceeds the configured maximum size for {max_targets} entries."
            )
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise TargetValidationError(f"Unable to read target file '{path}': {exc}") from None

    targets: list[Target] = []
    seen: set[tuple[TargetType, str]] = set()
    for line_number, line in enumerate(lines, start=1):
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            target = parse_target(candidate)
        except TargetValidationError as exc:
            raise TargetValidationError(f"Target file line {line_number}: {exc}") from None
        key = (target.type, target.value)
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)
        if len(targets) > max_targets:
            raise TargetValidationError(
                f"Target file exceeds the configured maximum of {max_targets} entries."
            )
    if not targets:
        raise TargetValidationError("Target file contains no targets.")
    return tuple(targets)
