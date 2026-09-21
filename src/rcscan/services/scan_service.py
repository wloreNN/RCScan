"""Application service for creating validated scans before network execution."""

from __future__ import annotations

from pathlib import Path

from rcscan.core.config import AppConfig
from rcscan.core.exceptions import AuthorizationError, TargetValidationError
from rcscan.models.scan import Scan, parse_ports
from rcscan.scope.models import Target
from rcscan.scope.parser import parse_target, parse_target_file
from rcscan.scope.validator import validate_targets_in_scope


class ScanService:
    """Complete every safety check and create a PENDING scan record."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def create_scan(
        self,
        *,
        target_value: str | None,
        targets_file: Path | None,
        scope_value: str | None,
        ports_value: str | None,
        authorization_confirmed: bool,
        allow_loopback: bool,
        allow_public_targets: bool = False,
    ) -> Scan:
        if not authorization_confirmed:
            raise AuthorizationError(
                "Authorization confirmation is required. Re-run with --confirm-authorized."
            )
        if (target_value is None) == (targets_file is None):
            raise TargetValidationError("Provide exactly one of --target or --targets.")

        targets = self._load_targets(target_value, targets_file)
        if len(targets) > self._config.scope.max_targets:
            raise TargetValidationError(
                f"Target count exceeds the configured maximum of "
                f"{self._config.scope.max_targets}."
            )
        authorized_scope = (parse_target(scope_value),) if scope_value is not None else ()
        validate_targets_in_scope(
            targets,
            authorized_scope,
            allow_loopback=self._config.scope.allow_loopback or allow_loopback,
            allow_public_targets=(
                self._config.scope.allow_public_targets or allow_public_targets
            ),
        )
        ports = parse_ports(
            ports_value or self._config.ports.preset,
            self._config.ports.max_ports,
        )
        return Scan(
            targets=targets,
            authorized_scope=authorized_scope,
            profile_name=self._config.profile.name,
            ports=ports,
            authorization_confirmed=True,
            loopback_allowed=self._config.scope.allow_loopback or allow_loopback,
        )

    def _load_targets(
        self, target_value: str | None, targets_file: Path | None
    ) -> tuple[Target, ...]:
        if target_value is not None:
            return (parse_target(target_value),)
        if targets_file is None:  # Narrowing for static type checking.
            raise TargetValidationError("A target source is required.")
        return parse_target_file(targets_file, self._config.scope.max_targets)
