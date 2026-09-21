"""Normalized target and target-type models."""

from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, ConfigDict


class TargetType(StrEnum):
    IP = "IP"
    NETWORK = "NETWORK"
    HOSTNAME = "HOSTNAME"


class Target(BaseModel):
    """A syntactically validated, normalized scan target."""

    model_config = ConfigDict(frozen=True)

    value: str
    type: TargetType

    def as_ip(self) -> IPv4Address | None:
        return IPv4Address(self.value) if self.type is TargetType.IP else None

    def as_network(self) -> IPv4Network | None:
        return IPv4Network(self.value) if self.type is TargetType.NETWORK else None
