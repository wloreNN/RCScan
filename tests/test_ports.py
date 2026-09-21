import pytest

from rcscan.core.exceptions import PortValidationError
from rcscan.models.scan import COMMON_TCP_PORTS, parse_ports


def test_common_port_preset() -> None:
    assert parse_ports("COMMON", max_ports=len(COMMON_TCP_PORTS)) == COMMON_TCP_PORTS


@pytest.mark.parametrize(
    ("specification", "expected"),
    [
        ("443", (443,)),
        ("443,80,443", (80, 443)),
        ("80-83", (80, 81, 82, 83)),
        (" 22, 80-82, 443 ", (22, 80, 81, 82, 443)),
        ("1,3-5,4", (1, 3, 4, 5)),
    ],
)
def test_parses_sorted_unique_ports(specification: str, expected: tuple[int, ...]) -> None:
    assert parse_ports(specification, max_ports=10) == expected


@pytest.mark.parametrize(
    ("specification", "message"),
    [
        ("", "cannot be empty"),
        ("80,", "empty item"),
        ("80--81", "Malformed port range"),
        ("90-80", "Reversed port range"),
        ("http", "Invalid port value"),
        ("1.5", "Invalid port value"),
        ("0", "between 1 and 65535"),
        ("65536", "between 1 and 65535"),
    ],
)
def test_rejects_invalid_port_specifications(specification: str, message: str) -> None:
    with pytest.raises(PortValidationError, match=message):
        parse_ports(specification, max_ports=100)


@pytest.mark.parametrize("specification", ["1-4", "1,2,3,4"])
def test_enforces_maximum_port_count(specification: str) -> None:
    with pytest.raises(PortValidationError, match="configured maximum of 3"):
        parse_ports(specification, max_ports=3)
