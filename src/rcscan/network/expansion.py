"""Expand validated targets into bounded concrete hosts without network access."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Network

from rcscan.network.errors import TargetExpansionError
from rcscan.network.models import ExpandedHost
from rcscan.scope.models import Target, TargetType


def expand_targets(targets: tuple[Target, ...], max_targets: int) -> tuple[ExpandedHost, ...]:
    """Expand IP/CIDR entries using ``IPv4Network.hosts`` semantics."""
    expanded: list[ExpandedHost] = []
    seen_addresses: set[str] = set()
    seen_hostnames: set[str] = set()

    for target in targets:
        if target.type is TargetType.HOSTNAME:
            if target.value not in seen_hostnames:
                seen_hostnames.add(target.value)
                expanded.append(
                    ExpandedHost(
                        target=target.value,
                        address=None,
                        hostname=target.value,
                    )
                )
                _enforce_limit(expanded, max_targets)
            continue

        addresses: Iterable[str] = (
            (target.value,)
            if target.type is TargetType.IP
            else (str(address) for address in IPv4Network(target.value).hosts())
        )
        for address in addresses:
            if address in seen_addresses:
                continue
            seen_addresses.add(address)
            expanded.append(ExpandedHost(target=target.value, address=address))
            _enforce_limit(expanded, max_targets)

    if not expanded:
        raise TargetExpansionError("Target expansion produced no usable hosts.")
    return tuple(expanded)


def _enforce_limit(hosts: list[ExpandedHost], max_targets: int) -> None:
    if len(hosts) > max_targets:
        raise TargetExpansionError(
            f"Expanded host count exceeds the configured maximum of {max_targets}; "
            "no network activity was started."
        )
