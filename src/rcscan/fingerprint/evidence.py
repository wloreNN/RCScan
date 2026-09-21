"""Helpers for bounded, terminal-safe server-controlled evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from rcscan.fingerprint.models import EvidenceSource, FingerprintEvidence


def safe_preview(data: bytes, *, limit: int = 512) -> str:
    """Decode untrusted bytes and escape terminal control characters."""
    decoded = data.decode("utf-8", errors="replace")
    pieces: list[str] = []
    length = 0
    for character in decoded:
        if character == "\r":
            rendered = "\\r"
        elif character == "\n":
            rendered = "\\n"
        elif character == "\t":
            rendered = "\\t"
        elif character.isprintable() and character != "\x1b":
            rendered = character
        else:
            rendered = f"\\x{ord(character):02x}"
        if length + len(rendered) > limit:
            break
        pieces.append(rendered)
        length += len(rendered)
    return "".join(pieces)


def make_evidence(
    source: EvidenceSource,
    summary: str,
    raw: bytes | None = None,
) -> FingerprintEvidence:
    return FingerprintEvidence(
        source=source,
        summary=summary,
        raw_preview=safe_preview(raw) if raw else None,
        timestamp=datetime.now(UTC),
    )
