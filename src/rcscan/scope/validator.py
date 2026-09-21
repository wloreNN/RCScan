"""Explicit authorization-scope and safety policy enforcement."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

from rcscan.core.exceptions import ScopeValidationError
from rcscan.scope.models import Target, TargetType

_PRIVATE_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
_LOOPBACK = IPv4Network("127.0.0.0/8")


def validate_targets_in_scope(
    targets: tuple[Target, ...],
    authorized_scope: tuple[Target, ...],
    *,
    allow_loopback: bool,
    allow_public_targets: bool,
) -> None:
    """Require every target to pass policy and be contained by explicit scope."""
    if not authorized_scope:
        raise ScopeValidationError("An explicit --scope is required.")
    for target in targets:
        if _is_loopback(target) and not allow_loopback:
            raise ScopeValidationError(
                f"Loopback target '{target.value}' is blocked; use --allow-loopback "
                "only for authorized local development."
            )
        if _is_public(target) and not allow_public_targets:
            raise ScopeValidationError(
                f"Public target '{target.value}' is blocked by the active configuration policy."
            )
        if not any(_contains(scope_entry, target) for scope_entry in authorized_scope):
            raise ScopeValidationError(
                f"Target '{target.value}' is outside the explicitly authorized scope."
            )


def _contains(scope_entry: Target, target: Target) -> bool:
    if scope_entry.type is TargetType.HOSTNAME or target.type is TargetType.HOSTNAME:
        return (
            scope_entry.type is TargetType.HOSTNAME
            and target.type is TargetType.HOSTNAME
            and scope_entry.value == target.value
        )
    if target.type is TargetType.IP:
        target_ip = IPv4Address(target.value)
        if scope_entry.type is TargetType.IP:
            return target_ip == IPv4Address(scope_entry.value)
        return target_ip in IPv4Network(scope_entry.value)
    if scope_entry.type is TargetType.NETWORK:
        return IPv4Network(target.value).subnet_of(IPv4Network(scope_entry.value))
    return False


def _is_loopback(target: Target) -> bool:
    if target.type is TargetType.IP:
        return IPv4Address(target.value) in _LOOPBACK
    if target.type is TargetType.NETWORK:
        return IPv4Network(target.value).overlaps(_LOOPBACK)
    return target.value == "localhost"


def _is_public(target: Target) -> bool:
    if _is_loopback(target):
        return False
    if target.type is TargetType.HOSTNAME:
        # Without DNS or an ownership system, hostnames cannot be proven private.
        return True
    if target.type is TargetType.IP:
        address = IPv4Address(target.value)
        return not any(address in network for network in _PRIVATE_NETWORKS)
    network = IPv4Network(target.value)
    return not any(network.subnet_of(private) for private in _PRIVATE_NETWORKS)
