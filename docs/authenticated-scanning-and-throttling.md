# Static authentication and polite throttling

RCScan 1.0 can attach operator-supplied static HTTP authentication context to
an authorized web assessment. RCScan does not perform a login flow; authenticate
separately and provide the resulting static header or cookie values.

```powershell
rcscan scan ... `
  --header "Authorization: Bearer TOKEN" `
  --header "X-Assessment: approved" `
  --cookie "session=VALUE" `
  --cookie "csrf=VALUE"
```

Both options are repeatable. Cookies are merged in supplied order into one
Cookie header. Duplicate cookie names are rejected to avoid ambiguity.
RCScan also rejects operator overrides for `Host`, `Content-Length`,
`Transfer-Encoding`, `Connection`, and `Cookie`; use `--cookie` for cookies.
Header and cookie values containing unsafe framing characters are rejected.

## Origin boundary

Static authentication is registered only for confirmed HTTP or HTTPS origins
derived from the authorized scan target. The context is available to HTTP
fingerprinting, discovery, reviewed active verification, and active-web
baseline/probe/confirmation requests. It is not attached to unrelated
protocols.

Redirects and HTML resources continue through existing same-origin
normalization. A different scheme, host, or port is a different origin and
receives no operator Authorization header or cookie. RCScan does not follow
cross-origin redirects during discovery.

This is deliberately not a browser cookie jar. Response `Set-Cookie` values
are not adopted for reauthentication or session renewal.

## Secret handling

Normal and verbose output state only that authentication context is configured.
Input errors do not reproduce supplied values. Authentication objects hide
values from diagnostic representations, and response headers/bodies are
redacted if a target reflects a configured secret. JSON, HTML, and SARIF
sanitization remains a final defensive layer.

Treat reports and local command history as security-sensitive even with these
controls.

## Polite throttling

Web requests share a per-origin throttle coordinator. Safe defaults are:

```yaml
web_throttling:
  min_request_interval_seconds: 0.05
  max_retry_after_seconds: 5
  max_transient_retries: 1
```

The coordinator spaces requests, recognizes HTTP 429, recognizes HTTP 503 when
`Retry-After` is supplied, and applies bounded exponential backoff to malformed
or absent 429 guidance and temporary transport failures. `Retry-After` supports
both delay-seconds and HTTP-date. Waits are capped, finite, and cancellation
aware.

All workers for an origin observe shared deferral state, so concurrent work
does not immediately continue after throttling. Active-web retries must reserve
the existing central request budget; the global and per-parameter limits still
win. Verbose diagnostics show only origin, status, retry number, and bounded
wait duration.

RCScan does not respond to blocking by changing identities or increasing
aggressiveness.

## Limitations

RCScan 1.0 does not perform automatic credential attacks, automatic login or
reauthentication, WAF evasion, proxy rotation, IP rotation, browser automation,
or authentication bypass.

## Local demonstration

Start the controlled server:

```powershell
python scripts\f3_auth_throttle_demo_server.py --port 8096
```

The server accepts only the synthetic values `Bearer demo-token` or
`session=demo-session` for protected routes. Its throttling route returns one
controlled 429 with `Retry-After: 1` and then succeeds.
