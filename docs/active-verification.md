# M6 Active Verification

## Boundary and enablement

M6 adds optional, bounded active verification after M5 finding generation. It is
disabled by default (`verification.enabled: false`). Enable it for one CLI scan with
`--active-verification`, or persistently in an explicit YAML profile with:

```yaml
verification:
  enabled: true
```

The effective setting is the logical OR of the profile value and the CLI flag; there
is no CLI disable override for a profile that enables verification. Enabling M6 does
not enable vulnerability lookup. The pipeline remains authorization and scope
validation, target expansion, discovery, port scan, fingerprinting, optional M4
lookup, M5 finding generation, then M6 verification. With no findings, M6 makes no
requests.

M6 is not a generic vulnerability scanner or exploitability engine. It does not
authenticate, submit payloads, execute proofs of concept, mutate state, crawl, or
derive probes from CVE text, references, ports, banners, or redirects. Only explicit,
reviewed registry rules can send a request.

## Reviewed rule registries

The synthetic registry remains separate and contains one demonstration rule:

- rule: `rcscan-m6-demo-marker`
- verifier: `synthetic-http-marker`
- exact finding identity: service `HTTP`, product `RCScanDemo`, version `1.0.0`,
  CVE `CVE-DEMO-M6-0001`
- request: `GET /rcscan-demo-status`
- expected body marker: `RCSCAN_M6_DEMO_OK`
- rule request limit: one; rule timeout: 2.0 seconds
- safety classification: `SYNTHETIC_READ_ONLY`

`CVE-DEMO-M6-0001` is not a real CVE. No CVE-specific production rule ships in M6B;
the production rules corroborate service identity only.

The production registry contains three target-agnostic identity rules. They behave
the same for localhost, LAN IPs, public IPs, and public hostnames after the existing
authorization, scope, loopback, and public-target policies permit the scan:

- `http-server-identity-nginx-v1`: exact product `nginx`;
- `http-server-identity-apache-v1`: exact product `Apache`; and
- `http-server-identity-microsoft-iis-v1`: exact product `Microsoft-IIS`.

Each rule supports HTTP and HTTPS `KNOWN_VULNERABILITY` findings with a present
observed version and CVE identity. It sends one `HEAD /` request, then strictly
compares the bounded `Server` product/version token with the finding. The rule limit
is one request and 2.0 seconds. Its expected evidence is a valid, non-redirect
response carrying the exact observed identity.

`VERIFIED` means only that the response header corroborated the service product and
version already used to generate the finding. It does not verify the CVE,
vulnerability presence, remediation state, or exploitability. The request is
low-impact because HEAD is a normal read-only HTTP operation, has no request body,
does not authenticate or mutate state, and remains under all central bounds.

Server headers are operator-controlled and can be spoofed or can identify a proxy
rather than the software processing the request, which limits positive evidence.
Servers and intermediaries can suppress or rewrite the header, and virtual-host
routing, network controls, redirects, truncation, or timeouts can cause false
negatives.

Any finding not supported by these explicit criteria is `SKIPPED` with exactly zero
verification requests. There is no fallback, fuzzy matching, CVE-description probe
generation, or generic guessing.

The rule model permits only the reviewed read-only HTTP methods `HEAD`, `GET`, and
`OPTIONS`; arbitrary methods cannot be represented. The sole shipped rule uses
`GET`. Rule paths must be absolute ASCII paths and cannot contain whitespace or
control characters.

## Result statuses

Verification produces a separate result with one of six statuses:

- `NOT_ATTEMPTED`: a matching verifier was selected, but the central per-finding,
  per-rule, or total request budget denied its request. It has low verification
  confidence and zero requests attempted.
- `VERIFIED`: a valid, bounded, non-redirect HTTP response contained the exact
  reviewed synthetic marker or strictly reconfirmed a production rule's service
  identity. This verifies only that indicator; it does not mean the finding is
  vulnerable or exploitable. The rule reports high verification confidence and one
  request attempted.
- `NOT_VERIFIED`: a valid, bounded, non-redirect HTTP response was received without
  the expected marker. This is not proof that the target is safe, unaffected, or
  remediated. The shipped rule reports medium verification confidence and one request
  attempted.
- `INCONCLUSIVE`: safe verification could not decide because transport failed or
  timed out, the response exceeded the byte limit, HTTP framing/status was malformed
  or absent, or the response was a redirect. It reports low verification confidence;
  the shipped rule has reserved and attempted its one request.
- `ERROR`: verifier selection or execution raised an unexpected non-cancellation
  exception. The error is isolated to that finding, reports low verification
  confidence, and records whatever central request count was already reserved.
- `SKIPPED`: no explicitly reviewed registry rule supports the finding. No request is
  made, and verification confidence is low.

These are verification-result meanings only. For every status, M6 does not change the
finding's published CVSS, derived severity, effective applicability, finding
confidence, or priority. The verification result has its own confidence field and is
rendered alongside the unchanged finding.

## Budgets and HTTP behavior

Built-in defaults are:

- at most 2 requests per finding;
- at most 20 requests across the verification stage;
- 2.0 seconds per request;
- 16,384 response bytes; and
- concurrency 2.

The applicable timeout is the smaller of the configured timeout and the rule timeout.
The applicable per-finding request ceiling is the smaller of the configured ceiling
and the rule's reviewed limit. Budget reservation is centralized and concurrency
safe.

The client connects only to the finding's exact `host` and `port`. The HTTP `Host`
header is that finding host with CR/LF removed and a 253-character cap; it is not
replaced from response content and does not include an added port. For HTTPS rules,
SNI is the finding host only when it is not an IP literal; IP literals send no SNI.
The TLS context is inspection-only: certificate verification and hostname checking
are disabled, so a completed request is not a certificate-trust result.

Responses are read under the timeout and byte bound. HTTP 3xx responses are returned
as `INCONCLUSIVE`; redirects are never followed, including same-host redirects.
There is no cross-host redirect request. M6 stores bounded parsed response data only
long enough to interpret the rule and emits bounded summaries rather than raw
response bodies.

## Cleanup, cancellation, isolation, and privacy

Every opened stream writer is closed in `finally`, and `wait_closed()` is awaited.
Cleanup is shielded during cancellation, after which cancellation is re-raised.
Worker tasks use structured concurrency; cancellation propagates through M6 and
causes the scan lifecycle to become `CANCELLED`.

Expected transport problems become `INCONCLUSIVE`. Unexpected per-finding verifier
problems become `ERROR` without stopping sibling findings. An unexpected failure of
the whole verification stage is caught by `ScanRunner`; M2-M5 scan, fingerprint,
candidate, and finding evidence is preserved and the otherwise successful scan can
still complete without verification results.

M6 makes no third-party verification call and sends no finding to NVD. A reviewed
request necessarily discloses the destination address, port, HTTP path, bounded
`Host` value, and RCScan active-verification user agent to the authorized target.
Do not enable it where that target-side disclosure or response observation is not
authorized. Raw response bodies are not printed or persisted by M6. Results remain
in memory and bounded CLI output.

False negatives remain possible because verification is default-off, the registry is
deliberately tiny, most NVD findings are unsupported, findings may not be generated,
budgets can be exhausted, and timeouts, truncation, malformed responses, redirects,
network controls, virtual-host routing, suppressed headers, or changed indicators can
prevent a decision.
`NOT_VERIFIED`, `INCONCLUSIVE`, `ERROR`, `NOT_ATTEMPTED`, `SKIPPED`, or absence of a
verification result must never be treated as proof of security.

## Synthetic localhost demonstration

Install the editable project first. Then use two PowerShell terminals in the
repository.

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

The server binds only `127.0.0.1:8081`. Acceptance is a successful demo exit showing
`Status: VERIFIED`, verifier `synthetic-http-marker`, and `Requests: 1`. Stop the
server with Ctrl+C. Both scripts accept the same optional `--port` value when 8081 is
unavailable.

## Production-rule localhost acceptance

The existing M4 synthetic nginx server can exercise the production rule without LAN
or Internet access. In terminal 1 run:

```powershell
python scripts/m4_nginx_test_server.py
```

In terminal 2 run:

```powershell
python scripts/m6_production_verification_demo.py
```

Acceptance is `Status: VERIFIED`, rule `http-server-identity-nginx-v1`, and
`Requests: 1`. The server and client use only `127.0.0.1:8080`; the synthetic CVE is
not real.

## Authorized arbitrary targets

RCScan can technically operate on arbitrary authorized domains and IPv4
addresses. Individual production verification rules are technology/finding-specific,
never target-specific. For an explicitly authorized public domain:

```text
rcscan scan --target authorized.example.com --scope authorized.example.com --ports 443 --confirm-authorized --allow-public-targets --skip-discovery --vuln-lookup --active-verification
```

`--allow-public-targets` only relaxes public-target classification for that scan. It
does not bypass matching scope, authorization confirmation, target limits, loopback
policy, or any other safety boundary. The command sends a verification request only
if earlier stages generate a finding matching an explicit production rule.

## Boundary

Active verification stays inside this explicitly registered boundary. Report files
are a separate stage documented in `reporting.md`. There is no findings database,
workflow, or dashboard.
