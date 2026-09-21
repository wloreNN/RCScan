import pytest

from rcscan.core.exceptions import TargetValidationError
from rcscan.scope.models import TargetType
from rcscan.scope.parser import parse_target


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("0.0.0.0", "0.0.0.0"),
        ("10.20.30.40", "10.20.30.40"),
        ("255.255.255.255", "255.255.255.255"),
    ],
)
def test_parse_ipv4(raw: str, normalized: str) -> None:
    target = parse_target(raw)

    assert target.type is TargetType.IP
    assert target.value == normalized


@pytest.mark.parametrize(
    "raw",
    ["256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.999"],
)
def test_rejects_malformed_ipv4(raw: str) -> None:
    with pytest.raises(TargetValidationError, match="Invalid IPv4 address"):
        parse_target(raw)


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("192.168.10.0/24", "192.168.10.0/24"),
        ("203.0.113.7/32", "203.0.113.7/32"),
    ],
)
def test_parse_ipv4_cidr(raw: str, normalized: str) -> None:
    target = parse_target(raw)

    assert target.type is TargetType.NETWORK
    assert target.value == normalized


@pytest.mark.parametrize(
    "raw",
    ["10.0.0.1/24", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/", "bad/24"],
)
def test_rejects_malformed_ipv4_cidr(raw: str) -> None:
    with pytest.raises(TargetValidationError, match="Invalid IPv4 CIDR"):
        parse_target(raw)


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("Example.COM", "example.com"),
        ("scanner.internal.", "scanner.internal"),
        ("a-b.example", "a-b.example"),
        ("localhost", "localhost"),
    ],
)
def test_normalizes_hostname(raw: str, normalized: str) -> None:
    target = parse_target(raw)

    assert target.type is TargetType.HOSTNAME
    assert target.value == normalized


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "bad..example",
        "-bad.example",
        "bad-.example",
        "bad_name.example",
        f"{'a' * 64}.example",
        f"{'a' * 250}.com",
        "host/path",
        r"host\path",
        " host.example",
        "host.example ",
        "host name",
    ],
)
def test_rejects_malformed_hostname(raw: str) -> None:
    with pytest.raises(TargetValidationError):
        parse_target(raw)


@pytest.mark.parametrize(
    "raw",
    ["http://example.com", "https://10.0.0.1/path"],
)
def test_rejects_urls(raw: str) -> None:
    with pytest.raises(TargetValidationError, match="URLs are not targets"):
        parse_target(raw)


@pytest.mark.parametrize("raw", ["example.com:443", "10.0.0.1:22"])
def test_rejects_host_with_port(raw: str) -> None:
    with pytest.raises(TargetValidationError, match="ports are not supported"):
        parse_target(raw)


@pytest.mark.parametrize("raw", ["::1", "2001:db8::1", "2001:db8::/32"])
def test_rejects_ipv6(raw: str) -> None:
    with pytest.raises(TargetValidationError, match="IPv6"):
        parse_target(raw)
