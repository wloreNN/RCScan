# M8A Passive Web Security Checks

## Enablement

M8A is disabled by default. `--web-checks` explicitly enables passive checks and
automatically enables bounded M7 web discovery. It may also be enabled with
`web_checks.enabled: true` in an explicit profile. Existing authorization, scope,
loopback, and public-target policy is unchanged.

M8A sends no requests of its own. Rules consume only sanitized headers, cookie
attribute metadata, bounded text previews, discovered paths, robots entries, and
sitemap URLs already collected by M7.

## Supported checks

- Missing Content-Security-Policy.
- Missing Strict-Transport-Security on HTTPS only.
- Missing X-Content-Type-Options.
- Missing Referrer-Policy.
- Missing frame protection through both CSP `frame-ancestors` and
  X-Frame-Options.
- Missing Secure on HTTPS session-like cookies.
- Missing HttpOnly or missing/weak SameSite on session-like cookies.
- Passive `Access-Control-Allow-Origin: *` plus
  `Access-Control-Allow-Credentials: true` indicator.
- Explicit HTTP `Server` product/version disclosure.
- Strong stack trace, framework debug, exception, database-detail, and local
  filesystem-path indicators in bounded text.
- Successfully fetched backup/metadata/debug-like paths that M7 discovered.
- Source-map/backup-like resource references exposed by fetched pages.
- Interesting sensitive-looking hints in robots or sitemap evidence.

Cookie values are discarded while parsing response headers. Findings retain only
cookie names and security attributes.

## Severity policy

Header omissions and passive CORS indicators are LOW. Server version and
robots/sitemap hints are INFORMATIONAL. Missing Secure on an HTTPS session-like
cookie, strong verbose error evidence, and successfully fetched sensitive-looking
artifacts are MEDIUM. M8A assigns no CVE and invents no CVSS score.

Findings are deduplicated deterministically by rule, origin, and relevant resource
scope. A representative affected URL is retained.

## Limitations

Headers, server names, paths, and error text can be intentionally generated,
rewritten by intermediaries, or vary by route. Missing headers can be intentional
for some response types. Cookie requirements depend on application behavior.
Artifact names and robots hints do not prove sensitive content. Passive CORS analysis
does not test arbitrary origins. These constraints can produce false positives and
false negatives.

M8A does not test SQL injection, XSS, SSRF, XXE, SSTI, command injection, path
traversal, NoSQL injection, authentication, authorization, file upload, or any other
exploit class. It does not submit forms, mutate parameters, fuzz, brute force, or
execute JavaScript.

## Local synthetic demonstration

Terminal 1:

```powershell
Set-Location <path-to-RCScan>
.\.venv\Scripts\Activate.ps1
python scripts/m8a_web_security_demo_server.py
```

Terminal 2:

```powershell
Set-Location <path-to-RCScan>
.\.venv\Scripts\Activate.ps1
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8083 --confirm-authorized --allow-loopback --skip-discovery --web-checks
```

Every issue, cookie value, error, path, and server identity in this demo is
synthetic. Acceptance should show multiple information-disclosure, security-header,
cookie, and CORS findings. Stop the server with Ctrl+C.

## Boundary

Passive checks do not send their own requests. Bounded active web checks are a
separate opt-in stage documented in `active-web-checks.md`.
