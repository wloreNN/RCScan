# Milestone 3 Service Fingerprinting

## Purpose and boundary

M3 adds conservative, evidence-first identification after authorized TCP scanning.
Only ports already classified `OPEN` are fingerprinted. The result may identify SSH,
HTTP, HTTPS, or generic TLS and may extract narrowly supported product/version fields.
When bounded evidence does not establish one of those services, the result is
`UNKNOWN`.

Fingerprinting is not CVE correlation, vulnerability detection, certificate
validation, exploitability analysis, or risk scoring. No fingerprint says that an
endpoint, product, version, or certificate is secure or vulnerable. Those
conclusions belong to later assessment stages.

## Per-port decision flow

Each open port follows this evidence sequence:

1. Open a plain connection and wait for a passive server banner. Read at most
   `max_banner_bytes`, plus one internal byte used only to detect truncation. No
   application payload is sent on this connection.
2. Inspect up to the first ten banner lines for a valid SSH server identification.
   Valid protocol prefixes are `SSH-2.0-` and `SSH-1.99-`. A match returns `SSH`
   immediately without active probes.
3. If SSH is not established, choose a conservative active-probe order. Ports 80,
   8000, 8080, and 8888 try plain HTTP before TLS. Every other port tries TLS before
   plain HTTP. These numbers are ordering hints only; they never identify a service.
4. HTTP tries `HEAD` first. If that response is not valid HTTP and probe budget
   remains, it makes at most one `GET` fallback. Both use `/`, HTTP/1.1, a bounded
   `Host`, `User-Agent: RCScan/<version>`, and `Connection: close`.
5. A successful TLS handshake establishes `TLS`. If budget remains, HTTP over a new
   TLS connection may refine that result to `HTTPS`; otherwise it remains `TLS`.
6. If no supported protocol is established, return `UNKNOWN` with bounded
   observation evidence and the latest sanitized probe error, when present.

On HTTP-first ports, failed `HEAD` and `GET` attempts can consume two active probes
before TLS. With the default budget of three, that leaves one TLS probe; a successful
handshake is then reported as `TLS` because no budget remains for HTTP over TLS. This
is a bounded, conservative consequence of probe ordering, not a port-based identity.

## Active-probe accounting

The initial passive banner connection is not counted as an active application probe.
`fingerprinting.max_probes_per_port` bounds only:

- each standalone TLS handshake: one probe;
- each plain HTTP `HEAD` or `GET`: one probe; and
- each HTTPS `HEAD` or `GET`, including its TLS connection: one probe.

The configured range is 1–3 and the default is 3. There is never more than one `GET`
fallback for one HTTP attempt. A valid passive SSH banner can therefore identify SSH
with zero active probes.

## Recognition rules

### SSH and OpenSSH

SSH requires a printable, length-bounded identification line matching the supported
SSH protocol forms. It receives `HIGH` confidence. Any valid software string is
retained as bounded metadata. Product and version are promoted only when the entire
software value matches `OpenSSH_<version>`; that yields product `OpenSSH`.

### HTTP

HTTP requires all of the following:

- a complete `CRLF CRLF` or `LF LF` header boundary within the bounded read;
- an ASCII `HTTP/1.0` or `HTTP/1.1` status line; and
- a three-digit status from 100 through 599.

Header names must use valid HTTP token characters. Valid framing with valid headers
is `HIGH` confidence. Valid framing and status with one or more malformed header
lines remains HTTP but is `MEDIUM`, and metadata records
`malformed_headers: true`. Selected bounded metadata includes Server, Content-Type,
Location, and Via. Product/version extraction uses only the first conservative token
of the `Server` value.

### TLS and HTTPS

TLS requires a completed TLS handshake and an available TLS session object. Bounded
metadata may include protocol version, cipher, and selected certificate fields.
That direct handshake evidence is `HIGH` confidence.

HTTPS requires both successful TLS inspection and a valid HTTP response received over
TLS. A familiar HTTPS port number, a certificate, or a successful handshake without
valid HTTP is not enough. HTTPS inherits TLS evidence/metadata and adds HTTP evidence.

### UNKNOWN

`UNKNOWN` is the required conservative result when no supported service is proven.
It has `LOW` confidence. It can retain an unrecognized passive banner, with control
characters escaped and its preview length limited, or a generic observation that no
recognizable bounded response was obtained. `UNKNOWN` does not mean closed, safe,
unsafe, or unsupported by the server; it describes only the evidence obtained within
the configured limits.

## Confidence meanings

- `HIGH`: direct, well-formed SSH identification, TLS handshake, or valid HTTP
  framing/status evidence.
- `MEDIUM`: valid HTTP framing/status evidence containing malformed header lines.
- `LOW`: no supported service was established; currently used for `UNKNOWN`.

Confidence measures the strength of service-identification evidence. It is not a
security severity, vulnerability likelihood, or risk rating.

## TLS inspection context and SNI

Each standalone TLS or HTTPS attempt creates a fresh `SSLContext`; there is no global
mutation or shared trust override. The context has hostname checking disabled and
uses `CERT_NONE` only to inspect the identity of explicitly authorized endpoints,
including self-signed or private-PKI services. Certificate metadata collected in this
mode is observational and must not be interpreted as trust validation.

Connections are made to the concrete resolved IPv4 address. SNI is sent only when the
original authorized target was a hostname, using that original normalized hostname.
IP and CIDR targets send no SNI. SNI is never inferred from DNS results, banners,
certificates, redirects, or HTTP responses. The HTTP `Host` header follows the same
identity rule: original hostname when present, otherwise the address.

## Resource, cleanup, and cancellation guarantees

Defaults and validated configuration bounds are:

- `timeout_seconds: 2.0` (greater than 0 through 30), independently enclosing each
  passive read, TLS handshake, or complete HTTP write/header read;
- `max_banner_bytes: 4096` (64 through 65,536);
- `max_header_bytes: 8192` (256 through 131,072);
- `max_probes_per_port: 3` (1 through 3); and
- `concurrency: 25` (1 through 250), enforced by a fingerprint-specific worker count
  and semaphore.

HTTP reads stop at the first complete header boundary or the configured byte limit;
response bodies are not intentionally read. Evidence previews are terminal-safe and
capped at 512 rendered characters. Errors are whitespace-normalized and bounded.

Every successfully created stream writer is closed in `finally`, and
`wait_closed()` is awaited. Closure is shielded during cancellation long enough to
finish cleanup, after which cancellation is re-raised. The fingerprint `TaskGroup`
cancels sibling workers, and `ScanRunner` records the scan as `CANCELLED`. Ordinary
probe failures do not abort the scan; they contribute to conservative fallback or
`UNKNOWN`.

## Disabling fingerprinting

Pass `--no-fingerprint` to retain discovery and TCP port scanning but make no passive,
TLS, or HTTP fingerprint connections:

```text
rcscan scan --target 127.0.0.1 --scope 127.0.0.1 --ports 8000 --confirm-authorized --allow-loopback --skip-discovery --no-fingerprint
```

Setting `fingerprinting.enabled: false` in strict YAML configuration has the same
fingerprint-stage effect. Neither option changes authorization, scope enforcement,
discovery, TCP state classification, or port-scan bounds.

## Known limitations

- M3 recognizes only bounded SSH, HTTP/1.0, HTTP/1.1, HTTPS, and generic TLS evidence.
- It does not actively send an SSH client identification, support HTTP/2 or HTTP/3,
  follow redirects, authenticate, read response bodies intentionally, or exhaustively
  negotiate application protocols.
- Quiet services may consume the passive timeout before active probes begin.
- Port hints are intentionally small and affect order only; services on unusual ports
  may be `UNKNOWN` within a reduced probe budget.
- `CERT_NONE` allows identity observation but supplies no certificate-chain,
  hostname, expiry, or revocation validation claim.
- Product/version extraction is deliberately narrow and may omit, truncate, or
  decline ambiguous server-controlled values.
- Fingerprinting itself adds no report file, findings database, dashboard, CVE
  mapping, vulnerability claim, or risk claim.
