"""Validated YAML configuration for RCScan."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)

from rcscan.core.exceptions import ConfigurationError


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProfileConfig(StrictModel):
    name: str = Field(default="safe-default", min_length=1, max_length=64)


class ScopeConfig(StrictModel):
    allow_loopback: bool = False
    allow_public_targets: bool = False
    max_targets: int = Field(default=256, ge=1, le=65_536)


class ScannerConfig(StrictModel):
    timeout_seconds: float = Field(default=2.0, gt=0, le=300)
    concurrency: int = Field(default=100, ge=1, le=1_000)
    retries: int = Field(default=1, ge=0, le=10)


PortNumber = Annotated[int, Field(ge=1, le=65_535)]


class DiscoveryConfig(StrictModel):
    enabled: bool = True
    ports: tuple[PortNumber, ...] = Field(
        default=(80, 443, 22, 445),
        min_length=1,
        max_length=16,
    )
    timeout_seconds: float = Field(default=1.0, gt=0, le=30)

    @field_validator("ports")
    @classmethod
    def normalize_ports(cls, ports: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(dict.fromkeys(ports))


class FingerprintingConfig(StrictModel):
    enabled: bool = True
    timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    max_banner_bytes: int = Field(default=4_096, ge=64, le=65_536)
    max_header_bytes: int = Field(default=8_192, ge=256, le=131_072)
    max_probes_per_port: int = Field(default=3, ge=1, le=3)
    concurrency: int = Field(default=25, ge=1, le=250)


class VulnerabilityConfig(StrictModel):
    enabled: bool = False
    provider: Literal["nvd"] = "nvd"
    nvd_api_key: SecretStr | None = None
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_response_bytes: int = Field(default=2_000_000, ge=1_024, le=10_000_000)
    max_references: int = Field(default=10, ge=0, le=50)
    max_candidates_per_identity: int = Field(default=100, ge=1, le=1_000)
    max_displayed_candidates: int = Field(default=10, ge=1, le=50)
    max_provider_requests_per_scan: int = Field(default=25, ge=1, le=100)
    cache_enabled: bool = True
    cache_ttl_hours: float = Field(default=24.0, gt=0, le=720)
    max_cache_entries: int = Field(default=256, ge=1, le=10_000)
    cache_path: Path | None = None


class FindingsConfig(StrictModel):
    enabled: bool = True
    max_displayed: int = Field(default=20, ge=1, le=100)


class VerificationConfig(StrictModel):
    enabled: bool = False
    max_requests_per_finding: int = Field(default=2, ge=1, le=10)
    max_total_requests: int = Field(default=20, ge=1, le=100)
    timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    max_response_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    concurrency: int = Field(default=2, ge=1, le=10)


class WebDiscoveryConfig(StrictModel):
    enabled: bool = False
    max_pages: int = Field(default=50, ge=1, le=500)
    max_depth: int = Field(default=2, ge=0, le=10)
    concurrency: int = Field(default=4, ge=1, le=20)
    timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    max_response_bytes: int = Field(default=262_144, ge=1_024, le=2_000_000)
    max_links_per_page: int = Field(default=100, ge=1, le=1_000)
    max_displayed: int = Field(default=10, ge=1, le=50)


class WebChecksConfig(StrictModel):
    enabled: bool = False
    max_displayed: int = Field(default=20, ge=1, le=100)


class ActiveWebChecksConfig(StrictModel):
    enabled: bool = False
    max_requests_per_parameter: int = Field(default=4, ge=1, le=8)
    max_total_requests: int = Field(default=30, ge=1, le=100)
    concurrency: int = Field(default=2, ge=1, le=10)
    timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    max_response_bytes: int = Field(default=262_144, ge=1_024, le=1_000_000)
    max_displayed: int = Field(default=20, ge=1, le=100)


class WebThrottlingConfig(StrictModel):
    min_request_interval_seconds: float = Field(default=0.05, ge=0, le=5)
    max_retry_after_seconds: float = Field(default=5.0, ge=0.1, le=60)
    max_transient_retries: int = Field(default=1, ge=0, le=3)


class PortsConfig(StrictModel):
    preset: str = "common"
    max_ports: int = Field(default=4_096, ge=1, le=65_535)


class AppConfig(StrictModel):
    profile: ProfileConfig = Field(default_factory=ProfileConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    fingerprinting: FingerprintingConfig = Field(default_factory=FingerprintingConfig)
    vulnerability: VulnerabilityConfig = Field(default_factory=VulnerabilityConfig)
    findings: FindingsConfig = Field(default_factory=FindingsConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    web_discovery: WebDiscoveryConfig = Field(default_factory=WebDiscoveryConfig)
    web_checks: WebChecksConfig = Field(default_factory=WebChecksConfig)
    active_web_checks: ActiveWebChecksConfig = Field(
        default_factory=ActiveWebChecksConfig
    )
    web_throttling: WebThrottlingConfig = Field(
        default_factory=WebThrottlingConfig
    )
    ports: PortsConfig = Field(default_factory=PortsConfig)


def load_config(path: Path | None = None) -> AppConfig:
    """Load a custom YAML file or return the built-in safe defaults."""
    if path is None:
        return _with_environment_secrets(AppConfig())
    try:
        loaded: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to load configuration '{path}': {exc}") from None
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ConfigurationError("Configuration root must be a YAML mapping.")
    try:
        return _with_environment_secrets(AppConfig.model_validate(loaded))
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise ConfigurationError(f"Invalid configuration: {details}") from None


def _with_environment_secrets(config: AppConfig) -> AppConfig:
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        return config
    vulnerability = config.vulnerability.model_copy(
        update={"nvd_api_key": SecretStr(api_key)}
    )
    return config.model_copy(update={"vulnerability": vulnerability})
