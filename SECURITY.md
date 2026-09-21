# Security Policy

## Authorized use

RCScan is intended only for defensive assessment of systems the operator owns or
has explicit, documented permission to test. Operators are responsible for defining
the permitted targets, ports, techniques, time window, and data handling before use.
The `--confirm-authorized` flag records an assertion; it does not create permission.

RCScan performs bounded TCP connect discovery, port-state assessment, limited
evidence-first SSH/HTTP/TLS identification, and optional CVE candidate correlation
only after all authorization, scope, policy, expansion, and port checks succeed. It
can derive structured potential findings, deterministic priorities, and
provenance-labelled guidance from existing candidates. Optional stages can crawl
the authorized origin, run reviewed passive and active web checks, attach a static
origin-bound authentication context, and write sanitized JSON, HTML, and SARIF
reports. It does not exploit, confirm exploitability, verify remediation, persist
findings in a database, or provide a dashboard.

## Scope enforcement

Each scan requires explicit authorization confirmation and an explicit scope entry for each
scan request. Every target must pass exact address/hostname or CIDR containment rules,
as applicable. Public targets are blocked by default, loopback requires a deliberate
local-development opt-in, and configured target, expansion, port, and concurrency
limits are enforced before connections begin.

Do not treat these controls as a complete authorization system. In particular,
RCScan does not verify asset ownership, contracts, identities, change windows, or
third-party approvals. The per-run `--allow-public-targets` flag and configuration
that permits public targets relax only that safety classification; neither proves
authorization nor disables scope containment.

## Vulnerability-intelligence privacy and interpretation

External lookup is disabled by default and requires `--vuln-lookup`, unless explicitly
enabled by the active profile; `--no-vuln-lookup` overrides an enabled profile.
RCScan queries the official NVD CVE API 2.0 only after an eligible fingerprint
normalizes through the small documented CPE map.

The outbound privacy boundary is exact: only the normalized CPE product/version is
sent. Target IP addresses, hostnames, scan IDs, banners, and response headers are
never sent to NVD. `NVD_API_KEY`, when supplied in the process environment, is sent
only as the NVD API key header. It is not stored in the provider-aware local cache,
and `.env` is not loaded automatically.

CVE identifies a published record, CPE identifies a product/version, and CVSS conveys
published severity. A `POTENTIAL_MATCH`, including a dotted-numeric range `MATCH`, is
not confirmation that the deployed service is vulnerable or exploitable. Complex
operating-system, hardware, application, negation, and other environment conditions
may remain `INDETERMINATE`.

An M4 candidate and an M5 finding are distinct. The candidate is provider correlation;
the finding is an endpoint-specific triage record derived from that correlation.
Published CVSS, CVSS-derived severity, effective applicability, evidence confidence,
and deterministic priority describe different inputs or decisions. None is
verification. `NO_MATCH` emits no finding; unresolved applicability and weaker
confidence reduce priority, with an informational floor. Missing CVSS is never
invented and produces `UNKNOWN` severity with informational priority.

Provider remediation is used only when both remediation text and its source are
present in candidate metadata; otherwise guidance is explicitly marked generic.
Guidance is advisory and does not prove applicability or successful remediation.
Stable IDs and within-scan deduplication are for deterministic identity, not
cross-scan tracking. Evidence, references, metadata, and CLI output are bounded.
Finding-generation failures remain isolated and preserve the original scan evidence.

False positives can result from banners, backports, stale provider records, or
unverified environment conditions. False negatives can result from bounded
fingerprinting/lookup, unsupported identities or versions, disabled lookup, provider
failure, and retained-candidate limits. A finding, `NO_MATCH`, or absence of findings
must not be treated as proof of security. See
[docs/findings-and-risk.md](docs/findings-and-risk.md).

NVD access is sequentially paced and response/time/request bounded. Rate-limit
`Retry-After` is honored within a bound. Malformed, oversized, unavailable, rejected,
or rate-limited provider responses remain optional enrichment failures and do not
fail the scan. The cache is TTL/size bounded, written by temporary-file replacement,
treats corruption as a miss, and contains no secrets.

## Active-verification safety and interpretation

Active verification is disabled by default and requires `--active-verification` or
`verification.enabled: true`. It does not enable vulnerability lookup. The shipped
registry contains one synthetic demonstration rule and three reviewed production
identity rules for nginx, Apache, and Microsoft IIS. Findings that do not match an
exact rule are `SKIPPED` with zero requests. There is no generic fallback probe.
Representable methods are reviewed `HEAD`, `GET`, and `OPTIONS`. The synthetic rule
uses one `GET`; the production identity rules use one `HEAD` and compare only the
bounded `Server` header with the identity already observed.

The default limits are 2 requests per finding, 20 total, a 2.0-second timeout, 16,384
response bytes, and concurrency 2. Redirects are never followed. Connections use the
finding host and port; `Host` uses the sanitized finding host, while HTTPS SNI uses it
only when it is not an IP literal. TLS certificate verification is disabled for this
inspection transport and must not be interpreted as certificate trust.

`VERIFIED` means only that the reviewed rule's expected evidence was observed, not
that a finding is exploitable. For the synthetic rule that evidence is a marker;
for the production rules it is a matching server identity. `NOT_VERIFIED` is not proof of safety. `NOT_ATTEMPTED`,
`INCONCLUSIVE`, `ERROR`, `SKIPPED`, and absence of a result likewise prove neither
security nor remediation. No verification status changes CVSS, severity,
applicability, finding confidence, or priority. Streams are closed and awaited,
cancellation propagates, and per-finding or whole-stage failures preserve earlier
scan and finding evidence.

Active verification sends no finding to a third-party verification service, but its reviewed request
discloses the destination, path, `Host`, and RCScan user agent to the authorized
target. Raw response bodies are not printed or persisted. See
[docs/active-verification.md](docs/active-verification.md) for exact status,
registry, privacy, failure, and false-negative boundaries.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the project maintainers through the
repository host's private security-advisory feature. Include:

- the affected version and environment;
- a concise description and security impact;
- minimal reproduction steps or a proof of concept;
- relevant logs with credentials, tokens, and personal data removed; and
- any suggested mitigation.

Do not open a public issue for an unpatched vulnerability. Allow maintainers reasonable
time to validate and remediate the report before disclosure. Do not access other
people's data, degrade services, use destructive payloads, or exceed the minimum
testing needed to demonstrate the issue.

## Unsupported and malicious uses

The project does not support unauthorized scanning or access, denial of service,
credential theft or brute force, persistence, evasion, malware delivery, exploitation
of third-party systems, surveillance, or collection/exfiltration of data without
permission. Requests for help enabling those activities may be declined. Users remain
responsible for applicable laws, contracts, and provider policies.

Only the current development line is maintained. No production support
or security-response service-level agreement is provided.
