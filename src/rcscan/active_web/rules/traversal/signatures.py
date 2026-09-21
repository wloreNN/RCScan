"""Deterministic structural signatures for low-sensitivity marker files."""

from __future__ import annotations

import re

from rcscan.active_web.rules.traversal.models import (
    TraversalPlatform,
    TraversalSignatureMatch,
)

_PASSWD_LINE = re.compile(
    r"^(?P<name>[a-z_][a-z0-9_-]*):(?:x|\*|!|):"
    r"(?P<uid>\d+):(?P<gid>\d+):[^:]*:(?P<home>/[^:]*):(?P<shell>/[^:]*)$",
    re.IGNORECASE,
)
_WIN_SECTION = re.compile(r"^\s*\[(?P<section>[A-Za-z ]{2,40})\]\s*$")


def match_standard_marker(body: bytes | str) -> TraversalSignatureMatch | None:
    text = (
        body.decode("ascii", errors="ignore")
        if isinstance(body, bytes)
        else body
    )[:32_768]
    unix = _match_unix_passwd(text)
    if unix is not None:
        return unix
    return _match_windows_ini(text)


def _match_unix_passwd(text: str) -> TraversalSignatureMatch | None:
    records = [
        match
        for line in text.splitlines()
        if (match := _PASSWD_LINE.fullmatch(line.strip())) is not None
    ]
    root = any(
        match.group("name").casefold() == "root" and match.group("uid") == "0"
        for match in records
    )
    system_accounts = {
        match.group("name").casefold()
        for match in records
        if int(match.group("uid")) < 1_000
    }
    shell_paths = {
        match.group("shell")
        for match in records
        if match.group("shell").startswith("/")
    }
    if len(records) < 3 or not root or len(system_accounts) < 3 or len(shell_paths) < 2:
        return None
    return TraversalSignatureMatch(
        marker_id="unix-passwd-structure",
        platform=TraversalPlatform.UNIX,
        reason=(
            f"Observed {len(records)} coherent account records including root UID 0, "
            f"{len(system_accounts)} system accounts, and multiple shell paths."
        ),
    )


def _match_windows_ini(text: str) -> TraversalSignatureMatch | None:
    sections = {
        match.group("section").strip().casefold()
        for line in text.splitlines()
        if (match := _WIN_SECTION.fullmatch(line)) is not None
    }
    required_secondary = {"extensions", "mci extensions", "files"}
    if "fonts" not in sections or not sections.intersection(required_secondary):
        return None
    if len(sections) < 3:
        return None
    return TraversalSignatureMatch(
        marker_id="windows-win-ini-structure",
        platform=TraversalPlatform.WINDOWS,
        reason=(
            "Observed coherent Windows initialization structure including a fonts "
            "section and an extensions/files section."
        ),
    )
