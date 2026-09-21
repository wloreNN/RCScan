import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from rcscan.vuln.cache import VulnerabilityCache, default_cache_path
from rcscan.vuln.models import (
    LookupProvenance,
    ProviderQueryResult,
    VulnerabilityRecord,
)

NOW = datetime.now(UTC)


def result(
    provider: str = "nvd", identity_key: str = "nginx|nginx|1.0"
) -> ProviderQueryResult:
    return ProviderQueryResult(
        provider=provider,
        identity_key=identity_key,
        records=(
            VulnerabilityRecord(
                cve_id="CVE-2026-1000",
                source="nvd",
                description="safe",
            ),
        ),
        lookup_at=NOW,
        provenance=LookupProvenance.LIVE,
    )


def cache(path: Path, *, ttl: float = 24, entries: int = 10) -> VulnerabilityCache:
    return VulnerabilityCache(path, ttl_hours=ttl, max_entries=entries)


def test_cache_round_trip_changes_provenance_to_cache(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "cache.json"
    cache(path).set(result())
    loaded = cache(path).get("nvd", "nginx|nginx|1.0")
    assert loaded is not None
    assert loaded.provenance is LookupProvenance.CACHE
    assert loaded.records[0].cve_id == "CVE-2026-1000"


def test_cache_is_provider_aware(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache(path).set(result("nvd"))
    assert cache(path).get("other", "nginx|nginx|1.0") is None


def test_expired_entry_is_a_miss(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache(path).set(result())
    document = json.loads(path.read_text(encoding="utf-8"))
    entry = next(iter(document["entries"].values()))
    entry["stored_at"] = (NOW - timedelta(hours=25)).isoformat()
    path.write_text(json.dumps(document), encoding="utf-8")
    assert cache(path).get("nvd", "nginx|nginx|1.0") is None


@pytest.mark.parametrize(
    "document",
    [
        "{",
        "[]",
        '{"schema_version":999,"entries":{}}',
        '{"schema_version":1,"entries":[]}',
        '{"schema_version":1,"entries":{"nvd|key":{"stored_at":"bad","result":{}}}}',
    ],
)
def test_corrupt_or_wrong_schema_cache_is_ignored(
    tmp_path: Path, document: str
) -> None:
    path = tmp_path / "cache.json"
    path.write_text(document, encoding="utf-8")
    assert cache(path).get("nvd", "key") is None


def test_oversized_cache_is_ignored_without_reading(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_bytes(b"x" * 10_000_001)
    with patch.object(Path, "read_text", side_effect=AssertionError("must not read")):
        assert cache(path).get("nvd", "key") is None


def test_max_entries_evicts_oldest(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    bounded = cache(path, entries=2)
    bounded.set(result(identity_key="one"))
    bounded.set(result(identity_key="two"))
    bounded.set(result(identity_key="three"))
    document = json.loads(path.read_text(encoding="utf-8"))
    assert len(document["entries"]) == 2
    assert "nvd|one" not in document["entries"]


def test_persistence_uses_temporary_file_then_atomic_replace(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    replacements: list[tuple[Path, Path]] = []
    original = Path.replace

    def recording_replace(source: Path, target: Path) -> Path:
        replacements.append((source, target))
        return original(source, target)

    with patch.object(Path, "replace", recording_replace):
        cache(path).set(result())

    assert path.exists()
    assert len(replacements) == 1
    assert replacements[0][0].suffix == ".tmp"
    assert replacements[0][1] == path
    assert not list(tmp_path.glob("*.tmp"))


def test_write_failure_is_swallowed_and_temporary_removed(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    with patch.object(Path, "replace", side_effect=OSError("disk failure")):
        cache(path).set(result())
    assert not path.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_cache_document_contains_no_provider_api_secret(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    secret = "super-secret-api-key"
    cache(path).set(result())
    assert secret not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("platform", "environment", "expected"),
    [
        (
            "win32",
            {"LOCALAPPDATA": r"C:\Users\Test\AppData\Local"},
            Path(r"C:\Users\Test\AppData\Local") / "RCScan/Cache/vulnerability-v1.json",
        ),
        (
            "linux",
            {"XDG_CACHE_HOME": "/var/tmp/cache"},
            Path("/var/tmp/cache/rcscan/vulnerability-v1.json"),
        ),
    ],
)
def test_default_cache_path_uses_platform_environment(
    platform: str, environment: dict[str, str], expected: Path
) -> None:
    with patch("rcscan.vuln.cache.sys.platform", platform), patch.dict(
        "os.environ", environment, clear=True
    ):
        assert default_cache_path() == expected


def test_default_macos_cache_path_uses_home() -> None:
    with patch("rcscan.vuln.cache.sys.platform", "darwin"), patch.object(
        Path, "home", return_value=Path("/Users/test")
    ):
        assert default_cache_path() == Path(
            "/Users/test/Library/Caches/RCScan/vulnerability-v1.json"
        )
