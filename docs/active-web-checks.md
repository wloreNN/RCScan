# M8B Controlled Active Web Checks

`--active-web-checks` explicitly enables controlled active GET checks and
automatically enables bounded M7 discovery. Without that flag or
`active_web_checks.enabled: true`, zero active probes are sent.

Only already-fetched, same-origin GET endpoints with discovered query parameter names
are eligible. One parameter is modified at a time while all other parameters are
preserved. Redirects are never followed by the transport. POST forms may be recorded
by M7 but are never submitted.

Authorization, explicit scope, loopback policy, and public-target policy are enforced
before this stage. `--active-web-checks` changes none of them, and
`--allow-public-targets` retains its existing semantics.

## Initial checks

The SQL injection indicator check appends one malformed quote to a parameter and
compares the bounded result with M7's baseline. A finding requires a new, strong
database/parser error signature. A generic 500 response or response-length change
alone is insufficient.

When errors are suppressed, the same rule sends small generic TRUE and FALSE
conditions and repeats the FALSE condition as confirmation. A finding requires the
baseline and TRUE responses to remain equivalent, the FALSE response to differ using
correlated status, normalized-body, length, stable-marker, or repeated-structure
signals, and the confirmation response to reproduce the FALSE behavior. Unstable,
random, or length-only differences are rejected.

The check performs no UNION query, stacked query, schema
enumeration, time delay, data extraction, file access, command execution, or
destructive SQL.

The reflected XSS indicator check sends a unique inert marker containing angle
brackets and quotes. It does not contain JavaScript and is never executed in a
browser. A finding requires byte-for-byte unescaped reflection in an HTML response.
Encoded reflection, absent reflection, and plain-text reflection do not produce a
finding.

Results are deliberately named `POTENTIAL_SQL_INJECTION` and
`POTENTIAL_REFLECTED_XSS`. They have no CVE or invented CVSS score.

## Adaptive path traversal / local file disclosure

The M8B-3 traversal subsystem is separated into reviewed rule models, a
structurally generated registry, eligibility and platform-aware selection,
deterministic marker signatures, and adaptive execution. Transport and global
budgets remain owned by the existing active-web engine.

Only discovered query parameters and same-origin GET-form inputs are considered.
Names such as `file`, `path`, `page`, `document`, `template`, `download`, and
`resource` receive an explainable eligibility score. Existing values containing
path separators or resembling filenames also contribute. Parameters without
file/path evidence are normally skipped with zero traversal requests.

The reviewed families cover canonical relative traversal, depth changes,
URL-encoded and repeated/double-decoding forms, slash/backslash separator forms,
Unix and Windows markers, and path-normalization variants. They are represented
as structured variants rather than a large duplicate payload list. Server
headers and observed path syntax infer `UNIX`, `WINDOWS`, or `UNKNOWN`; this
changes probe order but never changes scope authorization or permanently removes
the alternate platform family. Unknown targets begin with one Unix and one
Windows canonical probe.

Execution is staged:

1. At most two canonical cross-platform probes classify the response. No signal
   stops traversal testing for that parameter.
2. A bounded status/content-type or correlated body differential permits at most
   three evidence-directed depth, encoding, separator, or normalization variants.
3. A strong marker is repeated once with an uncached request. A finding requires
   the same structured signature on confirmation and its absence from baseline.

HTTP 200/404/500, response length, `root`, `windows`, “file not found,” and generic
errors are never sufficient findings. Unix matching requires multiple coherent
account-record fields including root UID 0, several system accounts, and shell
paths. Windows matching requires a coherent set of standard initialization
sections. Evidence retains only the marker identity, structural reason, rule
family, inferred platform, eligibility reason, and confirmation state—not the
retrieved body.

Traversal has a hard sub-cap of six requests per eligible parameter: two initial,
three adaptive, and one confirmation. The unchanged central default of four
active requests per parameter and 30 total requests always wins, so default
traffic remains lower. Budget exhaustion stops cleanly.

Confirmed strong signatures produce
`POTENTIAL_PATH_TRAVERSAL` / “Potential Path Traversal / Local File Disclosure.”
Confidence is HIGH when confirmation and strong path semantics are present, and
MEDIUM when eligibility is value-based but still sufficient. Weak differentials
produce no finding. Results have no CVE or invented CVSS score.

The marker pack deliberately targets only synthetic equivalents of standard
Unix account-file structure and Windows initialization-file structure. It does
not test private keys, password hashes, credential stores, cloud metadata,
environment files, application secrets, user documents, arbitrary files, or
operator-supplied file targets. It performs no enumeration, write, upload, or
code execution.

## Central limits

Defaults are four requests per parameter, 30 total requests, concurrency two, a
three-second timeout, and 262,144 response bytes. Budget reservation is centralized
and concurrency-safe. Timeouts, truncation, malformed responses, rule failures, and
budget exhaustion are isolated from the scan, M7 evidence, M8A findings, and sibling
active checks.

False positives and false negatives remain possible because applications can
generate synthetic parser text, filters and intermediaries can rewrite responses,
frameworks can normalize paths differently, and the checks use bounded
non-executing probe packs. Treat every result as a review lead, not proof of
exploitability.

Active web checks do not submit POST forms, perform login or re-authentication,
execute a browser, or test stored or DOM XSS, time-based SQL injection, arbitrary
file enumeration, sensitive-secret retrieval, SSRF, XXE, SSTI, command injection,
uploads, brute force, or exploitation. A static origin-bound header or cookie may
accompany the existing GET checks when the operator supplies one.

## Local synthetic demonstration

Terminal 1:

```powershell
Set-Location <path-to-RCScan>
.\.venv\Scripts\Activate.ps1
python scripts/m8b_active_web_demo_server.py
```

Terminal 2:

```powershell
Set-Location <path-to-RCScan>
.\.venv\Scripts\Activate.ps1
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8084 --confirm-authorized --allow-loopback --skip-discovery --web-discovery --web-checks --active-web-checks
```

The server is entirely synthetic and uses no database or host filesystem reads.
Acceptance should report
error-based and boolean-differential potential SQL injection indicators plus one
potential reflected XSS indicator and confirmed Unix/Windows traversal findings.
The safe comparison endpoints produce no matching vulnerability findings.
