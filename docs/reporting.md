# RCScan reporting

RCScan can export one completed scan to JSON, standalone HTML, and SARIF 2.1.0
without rerunning any network activity:

```powershell
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8091 `
  --confirm-authorized --allow-loopback --skip-discovery `
  --web-discovery --web-checks --active-web-checks `
  --report-json reports\scan.json `
  --report-html reports\scan.html `
  --report-sarif reports\scan.sarif
```

All exporters consume the same immutable canonical report model. The current
report schema version is `1.0`; JSON includes both `schema` and
`schema_version`. Timestamps use ISO-8601 and enum values are serialized as
stable strings.

## Evidence and redaction

Reports explain why a finding was generated using bounded summaries already
retained by RCScan. Default reports do not contain raw HTTP traffic or complete
response bodies. Local-file marker findings retain structural descriptions and
confirmation state, not disclosed file contents.

One centralized sanitizer is applied before export. It redacts authorization
and proxy-authorization values, cookies, set-cookie values, bearer tokens,
common API-token keys, password/secret/token-like query parameters, and
password-like metadata fields. Ordinary non-sensitive values remain available
where they help explain an observation. HTML additionally escapes all
target-controlled text and requires no JavaScript or external CDN.

Redaction is a safety boundary, not a substitute for handling reports as
security-sensitive records.

## JSON

JSON is deterministic, UTF-8, and pretty-printed by default. It contains scan
metadata, scope, selected features, network/service observations, advisory
correlation, web discovery, findings, sanitized reproduction evidence, and
summary counts.

## HTML

HTML is one responsive, print-friendly file with embedded CSS. It includes an
executive summary, scan/scope metadata, host and service summaries,
vulnerability-intelligence and web-discovery summaries, detailed findings,
methodology, confidence guidance, and limitations.

## SARIF

SARIF output follows SARIF 2.1.0. RCScan rule identifiers become SARIF rules,
and findings become results with conservative severity levels. Remote URLs are
represented as artifact URIs without fabricated source-code regions or line
numbers. RCScan-specific fields such as confidence, parameter, target,
platform, and confirmation remain in result properties.

SARIF consumers are code-scanning oriented, so some network-report structure is
necessarily retained as properties rather than native SARIF concepts.

## Failure behavior

Each report is written through a temporary file in the destination directory
and atomically replaced where supported. A requested report that cannot be
created produces an explicit reporting error and a non-zero CLI exit after the
completed scan result has been displayed. Temporary partial files are removed
when possible.
