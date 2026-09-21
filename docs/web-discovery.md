# M7 Bounded Web Discovery

## Enablement and boundary

Web discovery is disabled by default. Enable it for one authorized scan with
`--web-discovery`, or set `web_discovery.enabled: true` in an explicit profile.
Without either setting, the crawler is not called and makes zero requests.

M7 starts only from open ports already fingerprinted as HTTP or HTTPS. It records
web attack-surface structure for later milestones; it does not test vulnerabilities.
It never submits a form, authenticates, executes JavaScript, injects payloads,
guesses directories, fuzzes parameters, or sends POST, PUT, PATCH, or DELETE.

Authorization, explicit scope, target limits, loopback policy, and public-target
policy are enforced before scan execution. `--web-discovery` bypasses none of them.
The existing `--allow-public-targets` behavior is unchanged.

## Bounds

Safe defaults are:

- 50 fetched pages across the scan;
- depth 2;
- concurrency 4 across the crawler;
- 3-second request timeout;
- 262,144 response bytes;
- 100 discovered links considered per page; and
- 10 paths/forms displayed by the CLI.

The crawler uses bounded GET requests with `Connection: close`. HTTPS connects to the
resolved scan address while preserving the authorized hostname in the HTTP `Host`
header and TLS SNI.

## Same-origin and trap controls

Only URLs with the starting scheme, hostname, and effective port are eligible.
Fragments are removed. Relative paths are resolved and paths/query strings are
normalized. Duplicate URLs and repeated path/query-parameter shapes are suppressed.
Depth and page budgets are hard limits. `mailto:`, `javascript:`, `data:`, and `tel:`
references, credentials in URLs, control characters, repeated path-segment traps,
and common binary filename extensions are rejected.

Redirects are never followed automatically. A same-origin `Location` may be queued
under the normal budgets; a different-origin redirect is recorded but never
requested.

Only bounded HTML, XML, and text responses are parsed. Binary response bodies are
not read after their headers identify an unsuitable content type.

## Structured results

`WebDiscoveryResult` is separate from port fingerprints, findings, and verification
results. It distinguishes the fetched-page count from normalized discovered
endpoints, and contains query parameter names, forms and inputs, script URLs, useful
resource references, robots entries, sitemap URLs, and bounded errors. Both GET and
POST forms are recorded, but neither is submitted.

Malformed content, timeouts, truncation, and per-stage errors do not invalidate
existing scan results. Cancellation propagates after open streams are closed.

## Local demonstration

Install the editable project, then use two PowerShell terminals.

Terminal 1:

```powershell
Set-Location <path-to-RCScan>
.\.venv\Scripts\Activate.ps1
python scripts/m7_web_discovery_demo_server.py
```

Terminal 2:

```powershell
Set-Location <path-to-RCScan>
.\.venv\Scripts\Activate.ps1
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8082 --confirm-authorized --allow-loopback --skip-discovery --web-discovery
```

The summary should show discovered pages, two forms, one query parameter, and one
script. The external `outside.invalid` link must not be requested. Stop the server
with Ctrl+C.

## Boundary

Discovery data does not assert that any endpoint is vulnerable, safe, exploitable,
or remediated. Passive and active web checks are separate opt-in stages.
