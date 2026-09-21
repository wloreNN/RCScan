"""Small SSH identification parser."""

from __future__ import annotations

import re

from rcscan.fingerprint.evidence import make_evidence
from rcscan.fingerprint.models import (
    Confidence,
    EvidenceSource,
    Service,
    ServiceFingerprint,
)

_SSH_IDENTIFICATION = re.compile(
    rb"^SSH-(?P<protocol>2\.0|1\.99)-(?P<software>[!-~]{1,200})(?:[ \r\n]|$)"
)
_OPENSSH = re.compile(r"^OpenSSH_(?P<version>[A-Za-z0-9._+-]{1,64})$")


def parse_ssh_banner(data: bytes) -> ServiceFingerprint | None:
    """Recognize a valid bounded SSH server identification line."""
    for raw_line in data.splitlines()[:10]:
        if len(raw_line) > 255:
            continue
        match = _SSH_IDENTIFICATION.match(raw_line)
        if match is None:
            continue
        protocol = match.group("protocol").decode("ascii")
        software = match.group("software").decode("ascii")
        product: str | None = None
        version: str | None = None
        openssh = _OPENSSH.fullmatch(software)
        if openssh is not None:
            product = "OpenSSH"
            version = openssh.group("version")
        return ServiceFingerprint(
            service=Service.SSH,
            product=product,
            version=version,
            confidence=Confidence.HIGH,
            evidence=(
                make_evidence(
                    EvidenceSource.SERVER_BANNER,
                    f"Valid SSH-{protocol} server identification received.",
                    raw_line,
                ),
            ),
            probe_used="Passive banner",
            metadata={"protocol_version": protocol, "software": software[:128]},
        )
    return None
