"""Bounded defensive parsing for NVD CVE API responses."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from rcscan.vuln.errors import ProviderResponseError
from rcscan.vuln.models import AffectedRange, CVSSMetric, VulnerabilityRecord

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_nvd_response(
    document: Any,
    *,
    max_references: int,
    max_records: int,
) -> tuple[VulnerabilityRecord, ...]:
    if not isinstance(document, dict):
        raise ProviderResponseError("NVD response root is not an object.")
    vulnerabilities = document.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ProviderResponseError("NVD vulnerabilities field is not a list.")
    records: list[VulnerabilityRecord] = []
    seen: set[str] = set()
    for item in vulnerabilities[:max_records]:
        record = _parse_record(item, max_references)
        if record is None or record.cve_id in seen:
            continue
        seen.add(record.cve_id)
        records.append(record)
    return tuple(records)


def _parse_record(item: Any, max_references: int) -> VulnerabilityRecord | None:
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        return None
    cve: dict[str, Any] = item["cve"]
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id):
        return None
    return VulnerabilityRecord(
        cve_id=cve_id,
        source="nvd",
        published=_parse_datetime(cve.get("published")),
        last_modified=_parse_datetime(cve.get("lastModified")),
        description=_description(cve.get("descriptions")),
        cvss=_cvss_metrics(cve.get("metrics")),
        references=_references(cve.get("references"), max_references),
        affected=_affected_ranges(cve.get("configurations")),
        metadata={"source_identifier": str(cve.get("sourceIdentifier", ""))[:200]},
    )


def _description(value: Any) -> str:
    if not isinstance(value, list):
        return "No description supplied."
    descriptions = [item for item in value if isinstance(item, dict)]
    selected = next(
        (item.get("value") for item in descriptions if item.get("lang") == "en"),
        None,
    )
    if not isinstance(selected, str) and descriptions:
        selected = descriptions[0].get("value")
    return (
        " ".join(selected.split())[:2_000]
        if isinstance(selected, str) and selected.strip()
        else "No description supplied."
    )


def _cvss_metrics(value: Any) -> tuple[CVSSMetric, ...]:
    if not isinstance(value, dict):
        return ()
    metrics: list[CVSSMetric] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = value.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries[:3]:
            if not isinstance(entry, dict) or not isinstance(entry.get("cvssData"), dict):
                continue
            data = entry["cvssData"]
            try:
                metrics.append(
                    CVSSMetric(
                        version=str(data.get("version", ""))[:20],
                        base_score=float(data["baseScore"]),
                        base_severity=_optional_string(
                            data.get("baseSeverity") or entry.get("baseSeverity"),
                            30,
                        ),
                        vector=_optional_string(data.get("vectorString"), 300),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
    return tuple(metrics)


def _references(value: Any, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or limit == 0:
        return ()
    references: list[str] = []
    items = sorted(
        (item for item in value if isinstance(item, dict)),
        key=_reference_priority,
    )
    for item in items:
        url_value = item.get("url")
        if not isinstance(url_value, str):
            continue
        url = url_value[:500]
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        references.append(url)
        if len(references) >= limit:
            break
    return tuple(references)


def _reference_priority(item: dict[str, Any]) -> int:
    tags = item.get("tags", [])
    if not isinstance(tags, list):
        return 2
    normalized = {str(tag).casefold() for tag in tags}
    if "vendor advisory" in normalized:
        return 0
    if normalized & {"third party advisory", "us government resource"}:
        return 1
    return 2


def _affected_ranges(value: Any) -> tuple[AffectedRange, ...]:
    if not isinstance(value, list):
        return ()
    affected: list[AffectedRange] = []
    for configuration in value:
        if not isinstance(configuration, dict):
            continue
        matches, complex_conditions = _configuration_matches(configuration)
        for match in matches:
            parsed = _parse_cpe_match(match, complex_conditions)
            if parsed is not None:
                affected.append(parsed)
    return tuple(affected)


def _configuration_matches(
    configuration: dict[str, Any],
) -> tuple[list[dict[str, Any]], bool]:
    matches: list[dict[str, Any]] = []
    complex_conditions = False

    def visit(node: Any) -> None:
        nonlocal complex_conditions
        if not isinstance(node, dict):
            return
        if node.get("operator") == "AND" or node.get("negate") is True:
            complex_conditions = True
        cpe_matches = node.get("cpeMatch", [])
        if isinstance(cpe_matches, list):
            matches.extend(item for item in cpe_matches if isinstance(item, dict))
        children = node.get("children", [])
        if isinstance(children, list):
            for child in children:
                visit(child)

    nodes = configuration.get("nodes", [])
    if isinstance(nodes, list):
        for node in nodes:
            visit(node)
    if len(matches) > 1 and any(_cpe_part(item.get("criteria")) != "a" for item in matches):
        complex_conditions = True
    return matches, complex_conditions


def _parse_cpe_match(
    match: dict[str, Any],
    complex_conditions: bool,
) -> AffectedRange | None:
    parsed = _parse_cpe(match.get("criteria"))
    if parsed is None:
        return None
    vendor, product, version = parsed
    return AffectedRange(
        vendor=vendor,
        product=product,
        version=version,
        version_start_including=_optional_string(match.get("versionStartIncluding"), 100),
        version_start_excluding=_optional_string(match.get("versionStartExcluding"), 100),
        version_end_including=_optional_string(match.get("versionEndIncluding"), 100),
        version_end_excluding=_optional_string(match.get("versionEndExcluding"), 100),
        vulnerable=match.get("vulnerable") is True,
        conditions_unverified=complex_conditions,
    )


def _parse_cpe(value: Any) -> tuple[str, str, str | None] | None:
    if not isinstance(value, str) or not value.startswith("cpe:2.3:"):
        return None
    fields = _split_cpe(value[8:])
    if len(fields) < 4 or fields[0] != "a":
        return None
    version = fields[3] if fields[3] not in {"*", "-"} else None
    return _unescape(fields[1]), _unescape(fields[2]), _unescape(version) if version else None


def _split_cpe(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    fields.append("".join(current))
    return fields


def _unescape(value: str) -> str:
    result: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            result.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            result.append(character)
    return "".join(result)


def _cpe_part(value: Any) -> str | None:
    parsed = _parse_cpe(value)
    return "a" if parsed is not None else None


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _optional_string(value: Any, limit: int) -> str | None:
    return str(value)[:limit] if value not in (None, "") else None
