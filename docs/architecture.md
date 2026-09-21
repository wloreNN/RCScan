# Architecture

## Purpose

RCScan v1.0 provides authorized, bounded TCP scanning, evidence-first service
identification, optional vulnerability-candidate correlation, and deterministic
potential findings, followed by default-off active verification through an exact
reviewed-rule registry. Optional later stages add same-origin web discovery,
passive and active web checks, static origin-bound authentication, per-origin
throttling, and JSON, HTML, and SARIF reports. Those stages are documented in
[index.md](index.md).
Authorization, scope, and resource checks remain ahead of target expansion, hostname
resolution, discovery, port connections, fingerprinting, and provider lookup.

## Components

- `rcscan.cli`: Typer/Rich command surface, error handling, progress, cancellation
  handling, and human-readable results.
- `rcscan.core`: strict YAML settings, application exceptions, and logging setup.
- `rcscan.scope`: offline target parsing, normalization, classification, and
  authorization-scope enforcement.
- `rcscan.models`: immutable scan lifecycle data and port-specification parsing.
- `rcscan.services.ScanService`: validates authorization, scope, targets, and ports
  and creates a `PENDING` scan.
- `rcscan.services.ScanRunner`: owns lifecycle transitions, bounded expansion,
  post-validation hostname resolution, discovery, and host scan orchestration.
- `rcscan.network.expansion`: expands IPv4 addresses and CIDRs without network
  access and enforces the expanded-host limit.
- `rcscan.network.discovery`: derives conservative reachability evidence from TCP
  connect outcomes.
- `rcscan.network.tcp_scanner`: asynchronous TCP connect workers, shared semaphore,
  retries, timeouts, result classification, and stream cleanup.
- `rcscan.network.models`: immutable discovery, port, host, and run result models.
- `rcscan.fingerprint.probes`: time- and byte-bounded passive, HTTP, and TLS I/O,
  isolated TLS inspection contexts, and cancellation-safe stream cleanup.
- `rcscan.fingerprint.parsers`: conservative SSH and HTTP response parsing.
- `rcscan.fingerprint.engine`: evidence-first probe ordering, active-probe
  accounting, service classification, and a separate fingerprint worker pool.
- `rcscan.fingerprint.models`: immutable service, confidence, evidence, metadata,
  and error records attached to open `PortResult` objects.
- `rcscan.vuln.normalization` and `versioning`: the explicit product-to-CPE map and
  conservative dotted-numeric exact/range comparison.
- `rcscan.vuln.providers.nvd`: replaceable-provider implementation for the official
  NVD CVE API 2.0, including pacing, retries, and bounded parsing.
- `rcscan.vuln.cache`: provider-aware, TTL-bounded local JSON cache.
- `rcscan.vuln.engine`: per-scan identity deduplication, optional provider calls,
  candidate correlation, and sanitized per-port lookup failures.
- `rcscan.findings.policy`: CVSS-derived severity, deterministic priority,
  stable-ID, bounded-reference, and remediation-provenance policies.
- `rcscan.findings.engine`: isolated conversion of eligible M4 candidates into
  provider-independent findings using existing in-memory evidence only.
- `rcscan.findings.models`: immutable finding, evidence, severity, priority, and
  remediation records.
- `rcscan.verification.registry`: exact verifier selection, a separate synthetic
  demonstration registry, and three reviewed production identity rules; no generic
  fallback probes.
- `rcscan.verification.engine`: isolated workers and central per-finding/total
  request accounting.
- `rcscan.verification.http`: timeout/byte-bounded HTTP transport with no redirect
  following and cancellation-safe stream cleanup.
- `rcscan.verification.models`: immutable rules, six-state results, and bounded
  evidence.
- `rcscan.web`, `rcscan.active_web`, and `rcscan.reporting`: optional web
  discovery, passive and active checks, origin-bound request context, throttling,
  and canonical report export. See the focused documents linked from `index.md`.

## Execution flow

1. The CLI loads built-in defaults or a caller-supplied YAML configuration.
2. `ScanService` requires authorization confirmation and exactly one target source.
3. Targets and the one explicit scope entry are parsed without DNS or network access.
4. Scope policy checks loopback/public classification and containment.
5. Port input is normalized and bounded.
6. An immutable in-memory `Scan` begins as `PENDING`.
7. `ScanRunner` changes the lifecycle to `RUNNING` and expands authorized IPv4/CIDR
   targets, enforcing `scope.max_targets` before any network activity.
8. Each hostname, if present, is asynchronously resolved to its first IPv4 result only
   after validation. The authorization identity remains the exact normalized hostname.
9. Unless disabled, TCP connect discovery classifies the host as `REACHABLE`,
   `UNREACHABLE`, or `INCONCLUSIVE`.
10. Eligible hosts receive a bounded asynchronous TCP connect scan of the requested
    ports. Hosts are currently orchestrated sequentially; ports within the active host
    use a fixed-size worker pool.
11. Unless disabled by configuration or `--no-fingerprint`, only `OPEN` results enter
    a separate bounded fingerprint worker pool.
12. Each open port receives a passive banner connection. A valid SSH identification
    line ends probing immediately. Otherwise, TLS and HTTP active probes run in a
    conservative port-influenced order within `max_probes_per_port`.
13. External correlation is disabled by default. `--vuln-lookup` enables it;
    `--no-vuln-lookup` overrides a profile with `vulnerability.enabled: true`.
14. Eligible open-port fingerprints pass through the exact normalization map. Unique
    normalized identities use a fresh provider response or provider-aware cache entry.
15. NVD affected ranges are compared conservatively and retained only as
    `POTENTIAL_MATCH` candidates with explicit version and environment applicability.
16. When `findings.enabled` is true, eligible candidates on open, identified services
    are converted into deduplicated findings. Finding conversion performs no network
    activity and an unexpected failure preserves the scan and candidate evidence.
17. Active verification is disabled by default. It runs only when
    `verification.enabled` or `--active-verification` is true and findings exist.
18. Each finding is matched against the exact reviewed registry. Unsupported
    findings become `SKIPPED` with zero requests. The synthetic marker rule sends one
    reviewed `GET`; target-agnostic nginx, Apache, and Microsoft-IIS identity rules
    send one `HEAD` for exactly supported HTTP/HTTPS findings.
19. Immutable per-port, per-host, finding, and separate verification data is
    assembled into a
    `ScanRunResult`, and the
    lifecycle becomes `COMPLETED`. Cancellation and errors instead produce
    `CANCELLED` and `FAILED` lifecycle state respectively.

## Configuration boundary

Configuration is a strict YAML mapping: unknown fields are rejected.

- `profile.name`: display profile, 1–64 characters.
- `scope.allow_loopback`: persistent loopback opt-in; default `false`.
- `scope.allow_public_targets`: public-target policy opt-in; default `false`.
- `scope.max_targets`: 1–65,536; default 256.
- `scanner.timeout_seconds`: greater than 0 through 300; default 2.0.
- `scanner.concurrency`: 1–1,000; default 100.
- `scanner.retries`: 0–10; default 1.
- `discovery.enabled`: default `true`.
- `discovery.ports`: 1–16 TCP ports; default 80, 443, 22, and 445.
- `discovery.timeout_seconds`: greater than 0 through 30; default 1.0.
- `fingerprinting.enabled`: default `true`.
- `fingerprinting.timeout_seconds`: greater than 0 through 30; default 2.0, applied
  independently to each passive, TLS, or HTTP operation.
- `fingerprinting.max_banner_bytes`: 64–65,536; default 4,096.
- `fingerprinting.max_header_bytes`: 256–131,072; default 8,192.
- `fingerprinting.max_probes_per_port`: 1–3; default 3.
- `fingerprinting.concurrency`: 1–250; default 25.
- `vulnerability.enabled`: default `false`; CLI enable/disable flags override it.
- `vulnerability.provider`: currently only `nvd`.
- `vulnerability.nvd_api_key`: optional secret; `NVD_API_KEY` from the process
  environment overrides YAML.
- `vulnerability.request_timeout_seconds`: greater than 0 through 60; default 10.
- `vulnerability.max_response_bytes`: 1,024–10,000,000; default 2,000,000.
- `vulnerability.max_references`: 0–50; default 10.
- `vulnerability.max_candidates_per_identity`: 1–1,000; default 100.
- `vulnerability.max_displayed_candidates`: 1–50; default 10.
- `vulnerability.max_provider_requests_per_scan`: 1–100; default 25.
- `vulnerability.cache_enabled`: default `true`.
- `vulnerability.cache_ttl_hours`: greater than 0 through 720; default 24.
- `vulnerability.max_cache_entries`: 1–10,000; default 256.
- `vulnerability.cache_path`: optional path; otherwise the platform cache path.
- `findings.enabled`: default `true`.
- `findings.max_displayed`: 1–100; default 20.
- `verification.enabled`: default `false`; `--active-verification` can enable it.
- `verification.max_requests_per_finding`: 1–10; default 2.
- `verification.max_total_requests`: 1–100; default 20.
- `verification.timeout_seconds`: greater than 0 through 10; default 2.0.
- `verification.max_response_bytes`: 1,024–65,536; default 16,384.
- `verification.concurrency`: 1–10; default 2.
- `ports.preset`: default `common`.
- `ports.max_ports`: 1–65,535; default 4,096.

Port scanning consumes scanner timeout, concurrency, and retry settings. Discovery
uses its own timeout and ports and deliberately makes one attempt per discovery port.
Fingerprinting has separate timeout, byte, active-probe, and concurrency limits.
Vulnerability lookup has independent request, response, record, reference, cache, and
display bounds. Finding CLI output has its own complete-scan display bound.

## Active-verification boundary

The effective enablement is `verification.enabled OR --active-verification`; there is
no CLI disable override. The stage occurs strictly after M5 and does nothing without
findings. The separate synthetic registry contains the exact
`RCScanDemo` marker rule. The production registry contains target-agnostic nginx,
Apache, and Microsoft-IIS identity rules for HTTP/HTTPS known-vulnerability findings
with an observed version and CVE identity. Each production rule sends one `HEAD /`
and strictly compares the bounded `Server` token with the finding identity. Rule
models permit only reviewed `HEAD`, `GET`, and `OPTIONS` methods and absolute
CR/LF-free paths. No generic or inferred probe is implemented.

The central budget applies the smaller of configured per-finding and rule limits,
plus the configured total limit. The HTTP client connects to the finding's exact host
and port. `Host` is that host stripped of CR/LF and capped at 253 characters, without
an added port. For HTTPS, SNI is the finding host only when it is not an IP literal;
IP literals send no SNI. Its inspection TLS context disables certificate and hostname
verification. No redirect is followed; every 3xx is interpreted as `INCONCLUSIVE`.

The six result states are `NOT_ATTEMPTED` for budget denial, `VERIFIED` for the exact
reviewed marker or identity, `NOT_VERIFIED` for a valid bounded response without it,
`INCONCLUSIVE` for transport/timeout/truncation/malformed/redirect outcomes, `ERROR`
for an isolated unexpected verifier failure, and `SKIPPED` for no matching rule.
These results are annotations alongside immutable findings: no status changes CVSS,
severity, applicability, finding confidence, or priority. `VERIFIED` does not mean
exploitable, and `NOT_VERIFIED` does not mean safe.

Streams close in `finally`; `wait_closed()` is awaited and shielded during
cancellation before cancellation is re-raised. Per-finding failures are isolated.
The runner also isolates an unexpected whole-stage failure, preserving M2-M5
evidence. M6 has no third-party verification service or persistence, though a
reviewed request necessarily discloses its destination, path, `Host`, and user agent
to the target. See [active-verification.md](active-verification.md).

## Vulnerability-intelligence boundary

CVE identifies a disclosed vulnerability record; CPE identifies the normalized
vendor/product/version sent to NVD; CVSS is published severity metadata. None proves
that the scanned instance is vulnerable or exploitable. The exact map is `nginx` →
`nginx:nginx`, `openssh` → `openbsd:openssh`, `apache` and
`apache http server` → `apache:http_server`, and `microsoft-iis` →
`microsoft:internet_information_services`, after trim/whitespace/case normalization.
Only dotted-numeric versions are accepted; comparison zero-pads trailing components.

Affected ranges produce `MATCH`, `NO_MATCH`, or `INDETERMINATE`. A retained candidate
always remains `POTENTIAL_MATCH`. NVD `AND`, negated, or mixed platform/application
trees carry unverified environment conditions and therefore
`environment_applicability=INDETERMINATE`.

The NVD provider serializes pacing with a lock (6.0 seconds unauthenticated, 0.6 with
an API key), honors bounded `Retry-After` and retries one 429, retries one 5xx, streams
under the configured response-byte limit, and bounds parsed records and fields.
Provider and cache failures are optional enrichment failures attached to ports; they
do not fail the scan.

Unique normalized identities are queried once per run. The cache key includes provider
and `vendor|product|version`; default TTL is 24 hours. Cache writes use a temporary
file and atomic replacement, corrupt/oversized/invalid entries become misses, and no
API key or other secret is stored. Duplicate CVE IDs are removed in provider order.
The result model may retain 100 candidates by default while the CLI displays 10 and
reports the hidden count. Platform paths and all exact limits are documented in
[vulnerability-intelligence.md](vulnerability-intelligence.md).

For live product lookup, only the normalized CPE product/version is sent. Target IP,
hostname, scan ID, banner, and response headers are never sent.

## Findings and prioritization boundary

An M4 candidate is a provider record correlated with an observed normalized identity.
An M5 finding is the endpoint-specific representation of an eligible candidate; it
remains potential and does not confirm vulnerability, exploitability, or remediation.
Only open ports with a non-`UNKNOWN` fingerprint and supported normalized identity
can produce findings.

Effective applicability combines `affected_match` and
`environment_applicability`. Either `NO_MATCH` emits no finding; otherwise either
`INDETERMINATE` yields effective `INDETERMINATE`; only two `MATCH` values yield
effective `MATCH`. Published CVSS is retained as provider metadata. Derived severity
uses the base score: missing is `UNKNOWN`, `0.0` is `INFORMATIONAL`, greater than
`0.0`–less than `4.0` is `LOW`, `4.0`–less than `7.0` is `MEDIUM`,
`7.0`–less than `9.0` is `HIGH`, and `9.0`–`10.0` is `CRITICAL`.

Finding confidence is the candidate's M4 evidence confidence, not CVSS or exploit
probability. Priority starts from derived severity: effective `MATCH` plus `HIGH`
confidence is unchanged; `MATCH` plus `MEDIUM`, or `INDETERMINATE` plus
`HIGH`/`MEDIUM`, is reduced one level; `LOW` confidence is reduced two levels.
Missing CVSS maps to informational priority and reductions stop at the informational
floor.

The stable ID hashes normalized host, port, TCP service, vendor, product, and CVE ID
into `AF-` plus 24 hexadecimal characters. Duplicate IDs are removed within one scan
in traversal order, retaining the first. This is deterministic identity, not
persistent cross-scan state.

Finding evidence contains one generated observation, up to five fingerprint evidence
items, one normalized-identity item, and one correlation item. References retain at
most ten unique valid HTTP(S) values; verbose CLI output prints at most three per
finding. Metadata retains at most 20 bounded string entries and filters obvious
secret-key names. Complete-scan finding display defaults to 20 and is configurable
from 1 through 100, with hidden results counted.

Remediation is `PROVIDER` only when candidate metadata supplies both remediation text
and source; otherwise the engine uses explicitly `GENERIC` update-and-exposure
guidance. The current NVD parser does not derive remediation from ordinary
references. Per-candidate conversion failures are skipped. A whole-engine failure is
caught by `ScanRunner`, leaves findings empty, preserves scan/candidate evidence, and
does not change an otherwise successful scan to failed.

False positives remain possible from misleading banners, patched/backported versions,
stale records, and unresolved deployment conditions. False negatives remain possible
from bounded or disabled lookup, unsupported identities/versions, provider failure,
candidate limits, and malformed input. Absence of findings and `NO_MATCH` do not
prove security. Exact policy is documented in
[findings-and-risk.md](findings-and-risk.md).

## Evidence and classification

The engine classifies response evidence, never a port number by itself:

- `SSH` requires a syntactically valid `SSH-2.0-...` or `SSH-1.99-...`
  identification line within the first ten bounded banner lines. `OpenSSH_<version>`
  is the only SSH software form currently promoted into product `OpenSSH` and a
  version field; other valid software remains metadata.
- `HTTP` requires a complete header boundary and an ASCII HTTP/1.0 or HTTP/1.1 status
  line with a 100–599 status. It sends `HEAD / HTTP/1.1` first and at most one `GET`
  fallback if `HEAD` does not produce recognizable HTTP.
- `TLS` requires a completed TLS handshake with session metadata.
- `HTTPS` requires both successful TLS inspection and a valid HTTP response over TLS.
  TLS alone is never labeled HTTPS.
- `UNKNOWN` means the bounded observations did not establish SSH, HTTP, HTTPS, or
  TLS. An unrecognized passive banner is retained as escaped, length-limited evidence.

`HIGH` represents direct, well-formed protocol evidence: a valid SSH identification,
a successful TLS handshake, or valid HTTP framing and status. `MEDIUM` is used when
HTTP has a valid status line and boundary but one or more malformed header lines.
`LOW` indicates no supported service was established and is currently used for
`UNKNOWN`. Product and version extraction is opportunistic and does not alter these
meanings.

Port numbers influence only conservative ordering. Ports 80, 8000, 8080, and 8888 try
plain HTTP before TLS; other ports try TLS before plain HTTP. After TLS succeeds, the
engine attempts HTTP over TLS only if active-probe budget remains. The passive banner
connection does not count as an active application probe:
`max_probes_per_port` bounds only TLS and HTTP probes. Each HTTP method counts once,
and there can be at most one GET fallback.

## TLS identity-inspection boundary

Every TLS attempt creates a new explicit `SSLContext` for inspection of an authorized
endpoint. That context disables hostname checking and uses `CERT_NONE` so identity
inspection can observe self-signed, private-PKI, expired, or otherwise untrusted
authorized services. This is deliberately not a certificate-trust or security
validation result and the context is not global or reused for other application
traffic.

The network connection uses the resolved IPv4 address. SNI is supplied only when the
original authorized target was a hostname, and then uses that original normalized
hostname. IP/CIDR targets send no SNI. The HTTP `Host` value likewise uses the
original hostname when present, otherwise the address.

## Concurrency and resource bounds

`TCPScanner.scan_ports` places port numbers into an `asyncio.Queue` and starts at most
`scanner.concurrency` workers, further limited by the number of queued ports. Every
connection attempt also acquires the scanner's shared semaphore. Discovery and port
scanning use the same scanner instance, so the semaphore is the global connection
ceiling for that run even if orchestration becomes more parallel.

The worker pool prevents one task per selected port from being created at once.
Successful stream writers are closed and `wait_closed()` is awaited in `finally`.
Cancellation is re-raised rather than classified as a port error; `TaskGroup` then
cancels sibling work and `ScanRunner` records cancellation state.

Fingerprinting uses its own queue and `fingerprinting.concurrency` semaphore, capped
by the number of open ports. Every passive, HTTP, and TLS writer follows the same
close-and-await discipline. Writer closure is shielded long enough to complete during
cancellation; cancellation is then re-raised, causing sibling fingerprint work to be
cancelled and the scan lifecycle to become `CANCELLED`. Non-cancellation probe
failures are bounded evidence failures and can lead to `UNKNOWN`; unexpected
per-port fingerprint exceptions are sanitized into an `UNKNOWN` result.

## Result boundary

`PortResult` records host, TCP port, state, latency, timestamp, optional OS error
details, and an optional fingerprint. A fingerprint records service, optional
product/version, confidence, bounded evidence, probe labels, encryption state,
metadata, and a sanitized error. Server-controlled previews escape control characters
and are capped at 512 rendered characters. `HostScanResult` and `ScanRunResult` retain
the M2 lifecycle and count boundaries. Results remain in memory; there is no database
or report writer.

## Safety invariants

- Authorization confirmation never bypasses scope checks.
- Policy opt-ins never bypass scope containment.
- Hostname scope is exact-match only.
- Parsing targets, scopes, and ports is offline.
- DNS resolution occurs only after authorization and safety validation.
- Expanded-host limits are checked before network activity.
- `--skip-discovery` bypasses discovery; `--assume-up` only overrides inconclusive
  discovery, never explicit unreachability.
- Fingerprinting runs only after an open TCP result and can be disabled with
  `--no-fingerprint`.
- External vulnerability lookup is off by default and has explicit CLI enable/disable
  overrides.
- Finding generation is on by default, but can only consume candidates already
  present; vulnerability lookup remains off by default.
- `NO_MATCH` candidates do not become findings, and no finding is a verification
  result.
- Finding IDs, deduplication, scoring, bounds, and remediation provenance are
  deterministic and provider-independent.
- Active verification is off by default and runs only after findings.
- Unsupported findings are `SKIPPED` without a request; there are no generic probes.
- Verification never follows redirects or mutates finding scoring or applicability.
- Provider lookup receives only normalized CPE product/version, never target or raw
  fingerprint evidence.
- Provider failure remains optional and cannot convert a completed scan into failure.
- Port numbers never establish service identity.
- Passive banner collection sends no application payload and does not consume the
  active-probe budget.
- `max_probes_per_port` counts only TLS handshakes and HTTP requests.
- HTTPS requires TLS plus valid HTTP evidence.
- Request records begin as `PENDING`; only `PENDING` scans can execute.

## Out of scope

RCScan does not exploit targets, validate exploitability or remediation, calculate
organization-specific business risk, validate certificate trust, or perform
exhaustive protocol detection. Active verification stays inside its reviewed rule
registry. Candidates, findings, and verification statuses are not claims that a
service, product, version, certificate, or host is secure, exploitable, or
remediated. There is no findings database, workflow, or dashboard. Report files
are generated by the separate reporting stage documented in `reporting.md`.
