from pathlib import Path
from typing import Any

import pytest
import yaml

from rcscan.core.config import load_config
from rcscan.core.exceptions import ConfigurationError


def write_config(path: Path, data: Any) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_default_configuration_uses_safe_bounds() -> None:
    config = load_config()

    assert config.scope.allow_loopback is False
    assert config.scope.allow_public_targets is False
    assert config.scope.max_targets == 256
    assert config.scanner.timeout_seconds == 2.0
    assert config.scanner.concurrency == 100
    assert config.scanner.retries == 1
    assert config.fingerprinting.enabled is True
    assert config.fingerprinting.timeout_seconds == 2.0
    assert config.fingerprinting.max_banner_bytes == 4_096
    assert config.fingerprinting.max_header_bytes == 8_192
    assert config.fingerprinting.max_probes_per_port == 3
    assert config.fingerprinting.concurrency == 25
    assert config.findings.enabled is True
    assert config.findings.max_displayed == 20
    assert config.web_discovery.enabled is False
    assert config.web_discovery.max_pages == 50
    assert config.web_discovery.max_depth == 2
    assert config.web_discovery.concurrency == 4
    assert config.web_discovery.timeout_seconds == 3.0
    assert config.web_discovery.max_response_bytes == 262_144
    assert config.web_discovery.max_links_per_page == 100
    assert config.web_checks.enabled is False
    assert config.web_checks.max_displayed == 20
    assert config.active_web_checks.enabled is False
    assert config.active_web_checks.max_requests_per_parameter == 4
    assert config.active_web_checks.max_total_requests == 30
    assert config.active_web_checks.concurrency == 2
    assert config.active_web_checks.timeout_seconds == 3.0
    assert config.active_web_checks.max_response_bytes == 262_144
    assert config.web_throttling.min_request_interval_seconds == 0.05
    assert config.web_throttling.max_retry_after_seconds == 5
    assert config.web_throttling.max_transient_retries == 1
    assert config.ports.max_ports == 4096


def test_safe_default_profile_keeps_public_targets_blocked() -> None:
    config = load_config(Path("config/profiles/safe-default.yaml"))

    assert config.scope.allow_public_targets is False
    assert config.web_discovery.enabled is False
    assert config.web_checks.enabled is False
    assert config.active_web_checks.enabled is False


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("scope", "max_targets", 1),
        ("scope", "max_targets", 65_536),
        ("scanner", "timeout_seconds", 0.001),
        ("scanner", "timeout_seconds", 300),
        ("scanner", "concurrency", 1),
        ("scanner", "concurrency", 1_000),
        ("scanner", "retries", 0),
        ("scanner", "retries", 10),
        ("fingerprinting", "timeout_seconds", 0.001),
        ("fingerprinting", "timeout_seconds", 30),
        ("fingerprinting", "max_banner_bytes", 64),
        ("fingerprinting", "max_banner_bytes", 65_536),
        ("fingerprinting", "max_header_bytes", 256),
        ("fingerprinting", "max_header_bytes", 131_072),
        ("fingerprinting", "max_probes_per_port", 1),
        ("fingerprinting", "max_probes_per_port", 3),
        ("fingerprinting", "concurrency", 1),
        ("fingerprinting", "concurrency", 250),
        ("findings", "max_displayed", 1),
        ("findings", "max_displayed", 100),
        ("web_discovery", "max_pages", 1),
        ("web_discovery", "max_pages", 500),
        ("web_discovery", "max_depth", 0),
        ("web_discovery", "max_depth", 10),
        ("web_discovery", "concurrency", 1),
        ("web_discovery", "concurrency", 20),
        ("web_checks", "max_displayed", 1),
        ("web_checks", "max_displayed", 100),
        ("active_web_checks", "max_requests_per_parameter", 1),
        ("active_web_checks", "max_requests_per_parameter", 8),
        ("active_web_checks", "max_total_requests", 1),
        ("active_web_checks", "max_total_requests", 100),
        ("active_web_checks", "concurrency", 1),
        ("active_web_checks", "concurrency", 10),
        ("web_throttling", "min_request_interval_seconds", 0),
        ("web_throttling", "min_request_interval_seconds", 5),
        ("web_throttling", "max_retry_after_seconds", 0.1),
        ("web_throttling", "max_retry_after_seconds", 60),
        ("web_throttling", "max_transient_retries", 0),
        ("web_throttling", "max_transient_retries", 3),
        ("ports", "max_ports", 1),
        ("ports", "max_ports", 65_535),
    ],
)
def test_accepts_configuration_boundary_values(
    tmp_path: Path, section: str, field: str, value: int | float
) -> None:
    config = load_config(write_config(tmp_path / "config.yml", {section: {field: value}}))

    assert getattr(getattr(config, section), field) == value


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("scope", "max_targets", 0),
        ("scope", "max_targets", 65_537),
        ("scanner", "timeout_seconds", 0),
        ("scanner", "timeout_seconds", 301),
        ("scanner", "concurrency", 0),
        ("scanner", "concurrency", 1_001),
        ("scanner", "retries", -1),
        ("scanner", "retries", 11),
        ("fingerprinting", "timeout_seconds", 0),
        ("fingerprinting", "timeout_seconds", 31),
        ("fingerprinting", "max_banner_bytes", 63),
        ("fingerprinting", "max_banner_bytes", 65_537),
        ("fingerprinting", "max_header_bytes", 255),
        ("fingerprinting", "max_header_bytes", 131_073),
        ("fingerprinting", "max_probes_per_port", 0),
        ("fingerprinting", "max_probes_per_port", 4),
        ("fingerprinting", "concurrency", 0),
        ("fingerprinting", "concurrency", 251),
        ("findings", "max_displayed", 0),
        ("findings", "max_displayed", 101),
        ("web_discovery", "max_pages", 0),
        ("web_discovery", "max_pages", 501),
        ("web_discovery", "max_depth", -1),
        ("web_discovery", "max_depth", 11),
        ("web_discovery", "concurrency", 0),
        ("web_discovery", "concurrency", 21),
        ("web_checks", "max_displayed", 0),
        ("web_checks", "max_displayed", 101),
        ("active_web_checks", "max_requests_per_parameter", 0),
        ("active_web_checks", "max_requests_per_parameter", 9),
        ("active_web_checks", "max_total_requests", 0),
        ("active_web_checks", "max_total_requests", 101),
        ("active_web_checks", "concurrency", 0),
        ("active_web_checks", "concurrency", 11),
        ("web_throttling", "min_request_interval_seconds", -0.1),
        ("web_throttling", "min_request_interval_seconds", 5.1),
        ("web_throttling", "max_retry_after_seconds", 0),
        ("web_throttling", "max_retry_after_seconds", 61),
        ("web_throttling", "max_transient_retries", -1),
        ("web_throttling", "max_transient_retries", 4),
        ("ports", "max_ports", 0),
        ("ports", "max_ports", 65_536),
    ],
)
def test_rejects_configuration_values_outside_bounds(
    tmp_path: Path, section: str, field: str, value: int | float
) -> None:
    path = write_config(tmp_path / "config.yml", {section: {field: value}})

    with pytest.raises(ConfigurationError, match=rf"{section}\.{field}"):
        load_config(path)


@pytest.mark.parametrize("name", ["", "x" * 65])
def test_rejects_profile_name_outside_length_bounds(tmp_path: Path, name: str) -> None:
    path = write_config(tmp_path / "config.yml", {"profile": {"name": name}})

    with pytest.raises(ConfigurationError, match=r"profile\.name"):
        load_config(path)


def test_rejects_unknown_configuration_keys(tmp_path: Path) -> None:
    path = write_config(tmp_path / "config.yml", {"scanner": {"workers": 5}})

    with pytest.raises(ConfigurationError, match=r"scanner\.workers"):
        load_config(path)


def test_rejects_non_mapping_configuration_root(tmp_path: Path) -> None:
    path = write_config(tmp_path / "config.yml", ["not", "a", "mapping"])

    with pytest.raises(ConfigurationError, match="root must be a YAML mapping"):
        load_config(path)
