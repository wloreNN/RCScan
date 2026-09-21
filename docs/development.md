# Development Guide

## Environment

RCScan requires Python 3.12 or newer. Create and activate `.venv`, then install the
project and development tools:

```text
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

M6 optionally reads `NVD_API_KEY` from the process environment. It overrides a YAML
`vulnerability.nvd_api_key`, is passed only in the official NVD API request header,
and must never be logged, cached, or committed. `.env.example` is documentation only:
the application does not load `.env` files. Use the shell, process manager, or secret
manager to set the variable.

## Release packaging

Python 3.12 is the tested runtime. The package declares `requires-python >= 3.12`;
later versions are not part of the mandatory CI matrix. Built-in configuration
defaults live in Python, so the installed wheel does not require profile, report,
or demo files. `config/profiles/safe-default.yaml` remains a source example and is
selected only when `--config` points to it.

`src/rcscan/__init__.py` is the single version source. Build and packaging tools
belong to the `dev` extra, not the runtime install.

```text
python -m pip install -e ".[dev]"
python -m build
python -m twine check dist/*
```

Validate the wheel in a fresh environment, then run the commands from a directory
outside the source checkout:

```text
python -m venv .release-test-venv
.release-test-venv\Scripts\python -m pip install dist\rcscan-*.whl
rcscan --version
rcscan --help
python -m rcscan --help
```

The source distribution is validated the same way with `dist\rcscan-*.tar.gz`.
Remove `.release-test-venv` after the check. CI repeats pytest, Ruff, and mypy on
Ubuntu, Windows, and macOS, and builds both artifacts on Ubuntu.

## Checks

Run all applicable checks before proposing a change:

```text
python -m pytest
python -m pytest --cov=rcscan --cov-report=term-missing
python -m ruff check .
python -m mypy src/rcscan
```

## M6 development constraints

- Keep target, scope, configuration, port parsing, and IPv4/CIDR expansion
  deterministic and offline.
- Preserve explicit authorization confirmation and scope containment as independent
  checks.
- Keep every network action behind successful authorization and safety validation.
- Resolve hostname targets only after validation, retaining the normalized hostname as
  the authorization identity.
- Keep connection concurrency globally bounded and retain conservative timeout,
  retry, and error-classification behavior.
- Propagate cancellation and close every successfully created stream writer.
- Keep application-protocol probes under `rcscan.fingerprint`, separate from the
  TCP scanner abstraction and limited to ports proven open.
- Keep identification evidence-first: port numbers may influence probe order but must
  never establish a service.
- Preserve the passive-first path, valid SSH/OpenSSH parsing, HTTP `HEAD` with at most
  one `GET` fallback, and the TLS-plus-valid-HTTP requirement for HTTPS.
- Treat the passive banner connection separately from the active application-probe
  budget. `max_probes_per_port` bounds only TLS and HTTP probes.
- Create a fresh TLS inspection context for each TLS attempt. `CERT_NONE` and disabled
  hostname checks are restricted to authorized identity inspection; they must never
  be represented as certificate validation.
- Pass SNI only for the original authorized hostname. Never derive SNI from a resolved
  address, certificate, redirect, banner, or response.
- Preserve independent byte, per-operation timeout, active-probe, and fingerprint
  concurrency limits, terminal-safe evidence previews, cleanup, and cancellation.
- Keep `--no-fingerprint` as a complete opt-out from passive, TLS, and HTTP
  fingerprint connections after TCP scanning.
- Keep external lookup disabled by default. Preserve explicit `--vuln-lookup` and the
  `--no-vuln-lookup` override for enabled profiles; reject both together.
- Keep normalization exact and small: nginx, OpenSSH, Apache/Apache HTTP Server, and
  Microsoft-IIS only. Accept only dotted-numeric versions and do not guess vendor
  version semantics.
- Preserve three-state range results (`MATCH`, `NO_MATCH`, `INDETERMINATE`) and
  `POTENTIAL_MATCH` status. Candidates and published CVSS metadata must never be
  represented as confirmed vulnerability or exploitability.
- Keep NVD configuration/environment conditions conservative. `AND`, negation, and
  mixed platform/application conditions remain unverified and indeterminate.
- Keep the official NVD API provider sequentially paced, timeout/response bounded,
  respectful of bounded `Retry-After`, and optional on every provider failure.
- Preserve per-scan normalized-identity and per-response CVE deduplication, provider
  request/candidate/reference/display limits, and hidden-result counts.
- Keep candidates and findings distinct. Candidates are M4 provider correlations;
  findings are M5 endpoint-specific potential issues derived from existing evidence.
  Neither may be represented as active-verification or exploitability results.
- Preserve effective applicability: either `NO_MATCH` emits no finding; otherwise
  either `INDETERMINATE` wins; only `MATCH` plus `MATCH` is effective `MATCH`.
- Preserve exact derived-severity bands: missing CVSS is `UNKNOWN`, `0.0` is
  `INFORMATIONAL`, greater than `0.0`–less than `4.0` is `LOW`,
  `4.0`–less than `7.0` is `MEDIUM`, `7.0`–less than `9.0` is `HIGH`, and
  `9.0`–`10.0` is `CRITICAL`. Never invent a missing score.
- Preserve deterministic priority: effective `MATCH` plus `HIGH` confidence stays at
  severity; `MATCH` plus `MEDIUM`, or `INDETERMINATE` plus `HIGH`/`MEDIUM`, drops one
  level; `LOW` confidence drops two. Missing CVSS maps to informational priority and
  every reduction has an informational floor.
- Keep stable IDs based on host, port, TCP service, normalized vendor/product, and
  CVE ID. Deduplicate within a scan by ID in traversal order, retaining the first.
- Preserve evidence, description, reference, metadata, remediation, and CLI display
  bounds. `findings.enabled` defaults to true and `findings.max_displayed` defaults to
  20 (allowed 1–100); vulnerability lookup still defaults to false.
- Label remediation `PROVIDER` only when candidate metadata provides both text and
  source. Keep fallback guidance explicitly `GENERIC`; never infer remediation from
  an ordinary reference.
- Isolate malformed candidates and whole finding-engine failures without discarding
  scan/candidate evidence or failing an otherwise successful scan.
- Test false-positive and false-negative boundaries; absence of findings and
  `NO_MATCH` never prove security.
- Keep active verification disabled by default and after M5 finding generation.
  Preserve both opt-ins: `--active-verification` and `verification.enabled: true`.
- Keep the synthetic and production registries explicit and exact. Production rules
  must match technology/finding evidence, never target identity. Unsupported findings
  remain `SKIPPED` with zero requests; do not add generic, inferred, or fallback
  probes.
- Keep rule methods limited to reviewed `HEAD`, `GET`, and `OPTIONS`; the shipped
  synthetic rule uses one `GET` and each production identity rule uses one `HEAD`.
  Never follow redirects.
- Preserve verification defaults: 2 requests per finding, 20 total, 2.0 seconds,
  16,384 response bytes, and concurrency 2.
- Preserve exact finding-host connection and `Host` behavior. Send SNI only for a
  non-IP finding host; do not derive either value from redirects, banners,
  certificates, or response headers.
- Keep all six statuses semantically distinct. No status may mutate published CVSS,
  derived severity, effective applicability, finding confidence, or priority.
  `NOT_VERIFIED` never means safe and `VERIFIED` never means exploitable.
- Preserve writer cleanup, cancellation propagation, per-finding and whole-stage
  failure isolation, bounded evidence, no raw-body persistence, and target-side
  privacy disclosure documentation.
- Keep the cache provider-aware, TTL/entry/file-size bounded, atomically replaced,
  tolerant of corruption, and free of API keys or other secrets.
- Preserve the privacy boundary: send only normalized CPE product/version, never
  target IP, hostname, scan ID, banner, or response headers.
- Avoid adding secrets, real targets, authorization records, reports, or local
  artifacts to version control.
- Test loopback examples only against local services you control, and use
  `--allow-loopback` deliberately.

## Suggested test priorities

1. Target normalization and malformed input rejection.
2. The full IP/network/hostname containment matrix.
3. Public and loopback policy defaults and opt-ins.
4. Target-file UTF-8 handling, comments, deduplication, and limits.
5. Port presets, lists, ranges, bounds, and maximum counts.
6. IPv4/CIDR expansion, deduplication, and pre-network expansion limits.
7. Hostname resolution ordering, IPv4-only behavior, and failure results.
8. Cross-platform open, refused, timeout, unreachable, and unknown-error
   classification.
9. Discovery semantics, including refusal as reachability evidence and timeout as
   inconclusive.
10. `--skip-discovery` and `--assume-up`, including their mutual exclusion.
11. Global semaphore bounds, worker-pool limits, retries, cleanup, and cancellation.
12. Structured result counts, lifecycle transitions, CLI exit codes, and output.
13. Fingerprinting only open ports and bypass through configuration or
    `--no-fingerprint`.
14. Passive banner byte/time limits, SSH identification variants, OpenSSH
    product/version extraction, and escaped unrecognized evidence.
15. HTTP header byte/time limits, strict status-line/header-boundary recognition,
    `HEAD` success, and at most one `GET` fallback.
16. TLS inspection-context isolation, `CERT_NONE` scope, original-hostname-only SNI,
    metadata bounds, and HTTPS requiring TLS plus valid HTTP.
17. Probe ordering without port-based identity, active-probe accounting, `UNKNOWN`
    outcomes, and HIGH/MEDIUM/LOW confidence semantics.
18. Fingerprint worker/semaphore limits and cancellation-safe writer cleanup.
19. Exact product normalization, dotted-numeric parsing/zero padding, and
    `MATCH`/`NO_MATCH`/`INDETERMINATE` range boundaries.
20. Candidate-only semantics, complex-environment indeterminacy, CVSS selection, and
    CVE deduplication/display limits.
21. Lookup CLI override precedence, no-fingerprint behavior, NVD pacing,
    `Retry-After`, bounded parsing, and optional failure attachment.
22. Provider-aware cache TTL, eviction, platform defaults, atomic writes, corruption
    tolerance, and absence of secrets.
23. Outbound privacy assertions for CPE product/version only.
24. Candidate eligibility, effective applicability, `NO_MATCH` omission, and
    per-candidate failure isolation.
25. CVSS-derived severity boundaries, missing-score behavior, confidence reductions,
    and deterministic informational priority floor.
26. Stable finding IDs, traversal-order deduplication, bounded evidence/references/
    metadata/output, and secret-like metadata filtering.
27. Generic/provider remediation provenance and whole-engine failure isolation.
28. Default-off verification and CLI/config enablement, stage ordering, exact
    registry selection, unsupported-finding zero-request behavior, and no generic
    probes.
29. Six verification statuses, central budgets, method/path restrictions, no
    redirects, bounded parsing, Host/SNI rules, cleanup, cancellation, and failure
    isolation.
30. Verification immutability, privacy, false-negative boundaries, and explicit
    `NOT_VERIFIED`/`VERIFIED` interpretation limits.

## M4 and M5 demonstrations

Run the deterministic synthetic range demo offline:

```text
python scripts/m4_vuln_demo.py
```

It contacts no provider and uses `CVE-DEMO-0001`, which is not a real CVE. An optional
explicit live NVD request is:

```text
python scripts/m4_nvd_query.py nginx 1.24.0
```

The helper accepts only a supported product and dotted-numeric version and displays
the exact normalized CPE before lookup.

Run the parent-provided deterministic M5 findings demo offline:

```text
python scripts/m5_findings_demo.py
```

Accept it only when it exits successfully and reports `CVE-DEMO-0001` as CVSS 9.8
CRITICAL with `MATCH`, `HIGH` confidence, and `CRITICAL` priority. The second
`CVE-DEMO-0002` example must report `INDETERMINATE`, `MEDIUM` confidence, and reduced
`HIGH` priority. Both identifiers are synthetic; the output is not exploitation or
verification.

## M6 synthetic demonstration

Use two PowerShell terminals after installing the editable project.

Terminal 1:

```powershell
Set-Location <path-to-RCScan>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python scripts/m6_verification_demo_server.py
```

Terminal 2:

```powershell
Set-Location <path-to-RCScan>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python scripts/m6_verification_demo.py
```

Accept it only when the client exits successfully with `Status: VERIFIED`, verifier
`synthetic-http-marker`, and `Requests: 1`. The server binds only
`127.0.0.1:8081`; both scripts support a matching optional `--port`. The CVE and
marker are synthetic and demonstrate no exploitation.

## Windows PowerShell local acceptance

These commands intentionally target only loopback. First create and install the
development environment:

```powershell
Set-Location <path-to-RCScan>
py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src/rcscan
```

Keep that window open and start Python's loopback HTTP server:

```powershell
python -m http.server 8000 --bind 127.0.0.1
```

Open a second PowerShell window:

```powershell
Set-Location <path-to-RCScan>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8000 --confirm-authorized --allow-loopback --skip-discovery --verbose
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8000 --confirm-authorized --allow-loopback --skip-discovery --no-fingerprint
```

Accept the verbose scan only when it completes successfully and reports:

```text
8000/tcp   OPEN
Service     HTTP
Product     SimpleHTTP
Version     0.6
Confidence  HIGH
Probe        HTTP HEAD
Encrypted    no
Evidence     Valid HTTP status line and bounded headers received.
```

The Python runtime version may appear in the bounded `Server` metadata or evidence,
but the current conservative parser records the first server token as product
`SimpleHTTP` and version `0.6`. Accept the `--no-fingerprint` scan only when it reports
`8000/tcp OPEN` without a `Service` line. Stop the server with Ctrl+C.

## Current boundary

Active verification remains default-off and explicitly registered. It keeps the
synthetic demo rule separate from the reviewed production identity rules and does
not change finding assessment. RCScan performs no exploitation or exploitability
validation. JSON, HTML, and SARIF reports are implemented and documented in
`reporting.md`. There is no findings database, workflow, or dashboard.
