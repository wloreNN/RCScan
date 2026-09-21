"""Bounded, provider-aware local vulnerability intelligence cache."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from rcscan.vuln.models import LookupProvenance, ProviderQueryResult

SCHEMA_VERSION = 1
_MAX_CACHE_FILE_BYTES = 10_000_000


class VulnerabilityCache:
    def __init__(
        self,
        path: Path,
        *,
        ttl_hours: float,
        max_entries: int,
    ) -> None:
        self._path = path
        self._ttl = timedelta(hours=ttl_hours)
        self._max_entries = max_entries

    def get(self, provider: str, identity_key: str) -> ProviderQueryResult | None:
        document = self._read_document()
        entry = document["entries"].get(_entry_key(provider, identity_key))
        if not isinstance(entry, dict):
            return None
        try:
            stored_at = datetime.fromisoformat(str(entry["stored_at"]))
            if stored_at.tzinfo is None:
                return None
            if datetime.now(UTC) - stored_at > self._ttl:
                return None
            result = ProviderQueryResult.model_validate(entry["result"])
        except (KeyError, TypeError, ValueError, ValidationError):
            return None
        if result.provider != provider or result.identity_key != identity_key:
            return None
        return result.model_copy(update={"provenance": LookupProvenance.CACHE})

    def set(self, result: ProviderQueryResult) -> None:
        document = self._read_document()
        entries: dict[str, Any] = document["entries"]
        entries[_entry_key(result.provider, result.identity_key)] = {
            "stored_at": datetime.now(UTC).isoformat(),
            "result": _scrub_secret_fields(result.model_dump(mode="json")),
        }
        if len(entries) > self._max_entries:
            oldest = sorted(
                entries,
                key=lambda key: str(entries[key].get("stored_at", "")),
            )
            for key in oldest[: len(entries) - self._max_entries]:
                del entries[key]
        self._write_document(document)

    def _read_document(self) -> dict[str, Any]:
        try:
            if not self._path.exists():
                return _empty_document()
            if self._path.stat().st_size > _MAX_CACHE_FILE_BYTES:
                return _empty_document()
            document: Any = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return _empty_document()
        if not isinstance(document, dict):
            return _empty_document()
        if document.get("schema_version") != SCHEMA_VERSION:
            return _empty_document()
        if not isinstance(document.get("entries"), dict):
            return _empty_document()
        return document

    def _write_document(self, document: dict[str, Any]) -> None:
        temporary: Path | None = None
        try:
            payload = _serialize(document)
            entries: dict[str, Any] = document["entries"]
            while len(payload.encode("utf-8")) > _MAX_CACHE_FILE_BYTES and entries:
                oldest = min(
                    entries,
                    key=lambda key: str(entries[key].get("stored_at", "")),
                )
                del entries[oldest]
                payload = _serialize(document)
            if len(payload.encode("utf-8")) > _MAX_CACHE_FILE_BYTES:
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_name(f"{self._path.name}.{uuid4().hex}.tmp")
            temporary.write_text(payload, encoding="utf-8")
            temporary.replace(self._path)
        except OSError:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def default_cache_path() -> Path:
    if sys.platform == "win32":
        configured = os.getenv("LOCALAPPDATA")
        root = Path(configured) if configured else Path.home() / "AppData" / "Local"
        return root / "RCScan" / "Cache" / "vulnerability-v1.json"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "RCScan" / "vulnerability-v1.json"
    configured = os.getenv("XDG_CACHE_HOME")
    root = Path(configured) if configured else Path.home() / ".cache"
    return root / "rcscan" / "vulnerability-v1.json"


def _entry_key(provider: str, identity_key: str) -> str:
    return f"{provider}|{identity_key}"


def _empty_document() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "entries": {}}


def _scrub_secret_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _scrub_secret_fields(item)
            for key, item in value.items()
            if key.casefold().replace("-", "_")
            not in {"api_key", "apikey", "authorization", "token", "secret"}
        }
    if isinstance(value, list):
        return [_scrub_secret_fields(item) for item in value]
    return value


def _serialize(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=True, separators=(",", ":"))
