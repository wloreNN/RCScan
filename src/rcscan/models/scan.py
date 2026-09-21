"""Scan lifecycle model and port specification parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from rcscan.core.exceptions import PortValidationError
from rcscan.scope.models import Target

# Common TCP services: FTP, SSH, Telnet, SMTP, DNS, HTTP(S), mail, SMB,
# databases, remote desktop, alternate HTTP, and common development services.
COMMON_TCP_PORTS: tuple[int, ...] = (
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
)


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Scan(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: UUID = Field(default_factory=uuid4)
    targets: tuple[Target, ...]
    authorized_scope: tuple[Target, ...]
    profile_name: str
    ports: tuple[int, ...]
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    authorization_confirmed: bool
    loopback_allowed: bool = False


def parse_ports(specification: str, max_ports: int) -> tuple[int, ...]:
    """Normalize a port preset/list/range to sorted unique TCP port numbers."""
    value = specification.strip().lower()
    ports: set[int]
    if value == "common":
        ports = set(COMMON_TCP_PORTS)
    elif not value:
        raise PortValidationError("Port specification cannot be empty.")
    else:
        ports = set()
        for token in value.split(","):
            token = token.strip()
            if not token:
                raise PortValidationError("Port specification contains an empty item.")
            if "-" in token:
                parts = token.split("-")
                if len(parts) != 2:
                    raise PortValidationError(f"Malformed port range: {token}")
                start = _parse_port(parts[0], token)
                end = _parse_port(parts[1], token)
                if start > end:
                    raise PortValidationError(f"Reversed port range: {token}")
                if end - start + 1 > max_ports:
                    raise PortValidationError(
                        f"Port selection exceeds the configured maximum of {max_ports}."
                    )
                ports.update(range(start, end + 1))
            else:
                ports.add(_parse_port(token, token))
            if len(ports) > max_ports:
                raise PortValidationError(
                    f"Port selection exceeds the configured maximum of {max_ports}."
                )
    if len(ports) > max_ports:
        raise PortValidationError(
            f"Port selection exceeds the configured maximum of {max_ports}."
        )
    return tuple(sorted(ports))


def _parse_port(value: str, source: str) -> int:
    if not value.isdecimal():
        raise PortValidationError(f"Invalid port value: {source}")
    port = int(value)
    if not 1 <= port <= 65_535:
        raise PortValidationError(f"Port must be between 1 and 65535: {port}")
    return port
