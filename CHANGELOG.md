# Changelog

## 1.0.0 - 2026

First public release of RCScan, an evidence-driven vulnerability assessment scanner for explicitly authorized security testing.

- Authorization confirmation and strict scope enforcement, including loopback and public-target opt-ins
- Asynchronous TCP connect scanning and TCP host discovery
- Evidence-based HTTP, HTTPS, TLS, and SSH fingerprinting
- Conservative product, version, and CVE correlation that does not treat a match as exploitability
- Bounded same-origin web discovery
- Passive web security checks
- Active indicators for SQL injection, reflected XSS, and path traversal or local-file disclosure
- Static, origin-bound authenticated scanning
- Polite per-origin throttling with bounded `Retry-After` handling
- JSON, standalone HTML, and SARIF 2.1.0 reports from one canonical model
- Cross-platform Python packaging and a GitHub Actions matrix for Ubuntu, Windows, and macOS
