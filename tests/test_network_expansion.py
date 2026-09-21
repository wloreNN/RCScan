import pytest

from rcscan.network.errors import TargetExpansionError
from rcscan.network.expansion import expand_targets
from rcscan.scope.parser import parse_target


def test_expands_single_ip_without_network_access() -> None:
    hosts = expand_targets((parse_target("10.0.0.7"),), max_targets=1)

    assert [(host.target, host.address) for host in hosts] == [
        ("10.0.0.7", "10.0.0.7")
    ]


def test_expands_slash_30_to_usable_hosts_only() -> None:
    hosts = expand_targets((parse_target("10.0.0.4/30"),), max_targets=2)

    assert [host.address for host in hosts] == ["10.0.0.5", "10.0.0.6"]


def test_slash_31_uses_point_to_point_host_semantics() -> None:
    hosts = expand_targets((parse_target("10.0.0.8/31"),), max_targets=2)

    assert [host.address for host in hosts] == ["10.0.0.8", "10.0.0.9"]


def test_expansion_limit_is_enforced_before_network_execution() -> None:
    with pytest.raises(TargetExpansionError, match=r"maximum of 1.*no network activity"):
        expand_targets((parse_target("10.0.0.0/30"),), max_targets=1)


def test_expansion_deduplicates_overlapping_concrete_addresses() -> None:
    hosts = expand_targets(
        (parse_target("10.0.0.1"), parse_target("10.0.0.0/30")),
        max_targets=2,
    )

    assert [host.address for host in hosts] == ["10.0.0.1", "10.0.0.2"]
