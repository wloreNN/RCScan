# Network Scanning

Milestone 2 implements authorized IPv4 TCP connect discovery and port scanning. All
target parsing, policy checks, exact scope containment, authorization confirmation,
port validation, and expanded-host limits complete before network activity begins.

## Why TCP connect

RCScan uses `asyncio.open_connection`, which asks the operating system to complete
a normal TCP connection. This is portable and requires neither raw sockets nor
administrator/root privileges. It deliberately does not implement raw SYN scanning,
packet crafting, stealth behavior, or application-level probes.

A successful connection is `OPEN`. An explicit connection refusal is `CLOSED`: no
service accepted the connection on that port, but the refusal itself proves the host
was reachable. A successful stream is closed immediately and `wait_closed()` is
awaited; RCScan sends no application data.

On Windows, refusal may surface through Winsock code 10061 or the IOCP/ConnectEx
`ERROR_CONNECTION_REFUSED` code 1225. Both are classified as `CLOSED`. Verbose mode
logs the exception class, `errno`, `winerror`, attempt number, elapsed time, final
classification, and retry decision without printing a traceback.

## Conservative port states

- `OPEN`: the operating system completed the TCP connection.
- `CLOSED`: the destination explicitly refused the connection.
- `FILTERED`: the attempt timed out and no response was observed. This name does not
  prove that a firewall filtered traffic; packet loss, congestion, or a silent host
  can look identical from a TCP connect attempt.
- `ERROR`: the operating system returned an unreachable or another unclassified
  connection error.

Each immutable `PortResult` includes the host, port, TCP protocol, final state,
latency, timestamp, and optional operating-system error code and message.

The default requested-port timeout is 2 seconds with one retry. Only retryable
outcomes are retried: timeouts and a small set of transient abort/reset errors. Open,
refused, and explicit host/network-unreachable outcomes are final. Settings are
configurable within validated limits.

## Discovery

Discovery makes TCP connect attempts to configurable ports before scanning the
requested port set. Defaults are ports 80, 443, 22, and 445 with a 1-second timeout.
Discovery makes no retries.

- Any `OPEN` or `CLOSED` discovery result means `REACHABLE`; an explicit refusal is
  valid reachability evidence.
- If every discovery attempt is an `ERROR` with an explicit operating-system
  host/network-unreachable code, the host is `UNREACHABLE` and its port scan is
  skipped.
- Timeout-only, mixed, empty, and otherwise ambiguous evidence is `INCONCLUSIVE`.
  The requested port scan is skipped unless `--assume-up` is supplied.

`--skip-discovery` omits discovery attempts and scans requested ports directly.
`--assume-up` does not skip discovery: it allows scanning only after
`INCONCLUSIVE`, while `UNREACHABLE` remains skipped. The options cannot be combined.
Setting `discovery.enabled: false` in configuration behaves like skipped discovery.

Discovery is intentionally limited evidence. A host can be reachable even if all
configured discovery ports silently drop traffic; use `--assume-up` or
`--skip-discovery` only when that behavior is authorized and understood.

## Target expansion and hostname identity

Authorized IPv4 addresses remain single hosts. Strict IPv4 CIDRs expand with Python
`IPv4Network.hosts()` semantics, are deduplicated, and must remain within
`scope.max_targets`; exceeding the limit aborts before network activity.

Hostname authorization is based on the normalized, case-insensitive exact hostname,
not on DNS-derived addresses. Hostnames are conservatively classified as public and
require either the per-run `--allow-public-targets` opt-in or
`scope.allow_public_targets: true`, in addition to an exact hostname scope and
authorization confirmation. Neither opt-in bypasses scope. Only after those checks pass does the runner
asynchronously request IPv4 stream-socket records and select the first IPv4 address.
The resolved address is execution data attached to the authorized hostname identity;
it is not treated as a separately supplied target or as proof of ownership.
If it is loopback, the existing loopback policy is rechecked before any connection.

This ordering prevents DNS from widening scope during validation, but DNS remains
mutable. Operators must authorize and control the hostname and understand where it
resolves at execution time. IPv6-only hostnames fail resolution. Resolution failure
is recorded as a host error and discovery and port scanning are skipped for that host.

## Concurrency and scheduling

For one host, selected ports are queued in an `asyncio.Queue`. A fixed worker pool
contains at most `scanner.concurrency` tasks and never more workers than queued ports.
Workers take ports from the queue, await the final classified result including any
retry, report it, and continue until the queue is empty.

Every actual connection attempt also acquires one shared `asyncio.Semaphore` owned by
the scanner. The same scanner instance performs discovery and requested-port scans,
so the configured concurrency is a global ceiling on simultaneous connects in the
run. Current host orchestration is sequential; bounded parallelism occurs among ports
for the active host.

This queue-plus-semaphore design avoids creating one task per selected port and keeps
the connection bound intact across scanner users.

## Cleanup and cancellation

Every successful connection's writer is closed in `finally`, and close completion is
awaited. Cleanup errors are logged at debug level without replacing the classified
connection result.

`asyncio.CancelledError` is always re-raised. The worker `TaskGroup` cancels sibling
tasks, cleanup executes for connections already created, and `ScanRunner` transitions
its current lifecycle view to `CANCELLED`. Other execution exceptions transition it
to `FAILED`; successful runs transition to `COMPLETED`.

Results are immutable and in-memory. `HostScanResult` retains target identity,
resolved address, discovery evidence, timings, port results, and skip/error reasons.
`ScanRunResult` retains scan identity, lifecycle, host results, timing, and aggregate
counts.

## Limitations

Milestone 2:

- supports IPv4 execution only; IPv6 targets are rejected and hostname resolution
  requests IPv4 records only;
- accepts one explicit scope entry per CLI invocation;
- scans hosts sequentially, although ports use bounded asynchronous concurrency;
- uses TCP connect observations rather than packet-level evidence;
- cannot distinguish firewall filtering from other causes of silence;
- stores results only in memory;
- performs no UDP scanning and sends no application payloads.

This stage performs no application fingerprinting, CVE correlation, web checks, or
report generation. Those later stages are documented separately. There is no
dashboard.
