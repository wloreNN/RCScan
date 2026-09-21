import pytest

from rcscan.core.exceptions import ScopeValidationError
from rcscan.scope.parser import parse_target
from rcscan.scope.validator import validate_targets_in_scope


def validate(
    target: str,
    scope: str,
    *,
    allow_loopback: bool = False,
    allow_public_targets: bool = False,
) -> None:
    validate_targets_in_scope(
        (parse_target(target),),
        (parse_target(scope),),
        allow_loopback=allow_loopback,
        allow_public_targets=allow_public_targets,
    )


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("10.1.2.3", "10.1.2.3"),
        ("10.1.2.3", "10.0.0.0/8"),
        ("192.168.1.0/24", "192.168.0.0/16"),
        ("172.16.0.0/12", "172.16.0.0/12"),
    ],
)
def test_ip_and_cidr_scope_containment(target: str, scope: str) -> None:
    validate(target, scope)


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("10.1.2.4", "10.1.2.3"),
        ("10.0.0.0/8", "10.0.0.0/16"),
        ("192.168.2.0/24", "192.168.1.0/24"),
        ("10.1.2.0/24", "10.1.2.3"),
    ],
)
def test_rejects_targets_outside_ip_or_subnet_scope(target: str, scope: str) -> None:
    with pytest.raises(ScopeValidationError, match="outside"):
        validate(target, scope)


def test_hostname_scope_requires_normalized_identity() -> None:
    validate("App.Example.", "app.example", allow_public_targets=True)

    with pytest.raises(ScopeValidationError, match="outside"):
        validate("api.example", "app.example", allow_public_targets=True)


def test_hostname_and_ip_scope_types_do_not_cross_match() -> None:
    with pytest.raises(ScopeValidationError, match="outside"):
        validate("example.test", "10.0.0.0/8", allow_public_targets=True)


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("127.0.0.0/24", "127.0.0.0/8"),
        ("localhost", "localhost"),
    ],
)
def test_loopback_is_blocked_by_default(target: str, scope: str) -> None:
    with pytest.raises(ScopeValidationError, match="Loopback target"):
        validate(target, scope)


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("127.0.0.1", "127.0.0.0/8"),
        ("127.1.0.0/16", "127.0.0.0/8"),
        ("localhost", "localhost"),
    ],
)
def test_loopback_can_be_explicitly_allowed(target: str, scope: str) -> None:
    validate(target, scope, allow_loopback=True)


def test_public_target_is_blocked_by_default() -> None:
    with pytest.raises(ScopeValidationError, match="Public target"):
        validate("203.0.113.9", "203.0.113.0/24")


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("203.0.113.9", "203.0.113.0/24"),
        ("example.com", "example.com"),
    ],
)
def test_public_target_can_be_allowed(target: str, scope: str) -> None:
    validate(target, scope, allow_public_targets=True)


def test_explicit_scope_is_required() -> None:
    with pytest.raises(ScopeValidationError, match="explicit --scope"):
        validate_targets_in_scope(
            (parse_target("10.0.0.1"),),
            (),
            allow_loopback=False,
            allow_public_targets=False,
        )
