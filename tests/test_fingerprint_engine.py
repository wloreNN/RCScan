import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, call

import pytest

from rcscan.fingerprint.engine import FingerprintEngine
from rcscan.fingerprint.models import Service
from rcscan.fingerprint.probes import ReadProbeResult, TLSProbeResult
from rcscan.network.models import PortResult, PortState


def read(
    data: bytes = b"",
    *,
    error: str | None = None,
    truncated: bool = False,
) -> ReadProbeResult:
    return ReadProbeResult(
        data=data,
        latency_ms=1,
        error=error,
        truncated=truncated,
    )


def tls(
    succeeded: bool,
    *,
    error: str | None = None,
    version: str | None = None,
    cipher: str | None = None,
    certificate: dict[str, str] | None = None,
) -> TLSProbeResult:
    return TLSProbeResult(
        succeeded=succeeded,
        latency_ms=1,
        error=error,
        version=version,
        cipher=cipher,
        certificate=certificate,
    )


def engine(probe, *, concurrency: int = 3, max_probes: int = 3) -> FingerprintEngine:
    return FingerprintEngine(
        probe_client=probe,
        concurrency=concurrency,
        max_probes_per_port=max_probes,
    )


def port(number: int, state: PortState = PortState.OPEN) -> PortResult:
    return PortResult(
        host="10.0.0.1",
        port=number,
        state=state,
        latency_ms=1,
        timestamp=datetime.now(UTC),
    )


def test_engine_recognizes_ssh_on_nonstandard_port_without_active_probes() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read(b"SSH-2.0-OpenSSH_9.9\r\n")

    result = asyncio.run(
        engine(probe).fingerprint_port(
            address="10.0.0.1", port=65022, hostname=None
        )
    )

    assert result.service is Service.SSH
    assert result.product == "OpenSSH"
    probe.tls.assert_not_awaited()
    probe.http.assert_not_awaited()


def test_engine_finds_plain_http_on_random_nonstandard_port() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read()
    probe.tls.return_value = tls(False, error="not TLS")
    probe.http.return_value = read(b"HTTP/1.1 200 OK\r\nServer: unit/2.0\r\n\r\n")

    result = asyncio.run(
        engine(probe).fingerprint_port(
            address="10.0.0.1", port=54321, hostname="unit.internal"
        )
    )

    assert result.service is Service.HTTP
    assert result.product == "unit"
    probe.http.assert_awaited_once_with(
        "10.0.0.1",
        54321,
        method="HEAD",
        host_header="unit.internal",
        use_tls=False,
        server_hostname="unit.internal",
    )


def test_engine_returns_tls_only_with_bounded_metadata() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read()
    probe.tls.return_value = tls(
        True,
        version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        certificate={"subject": "unit", "notAfter": "tomorrow"},
    )
    probe.http.side_effect = [read(b"garbage"), read()]

    result = asyncio.run(
        engine(probe).fingerprint_port(
            address="10.0.0.1", port=443, hostname="unit.internal"
        )
    )

    assert result.service is Service.TLS
    assert result.encrypted is True
    assert result.metadata == {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "certificate_subject": "unit",
        "certificate_notAfter": "tomorrow",
    }
    assert probe.http.await_count == 2


def test_engine_upgrades_tls_to_https_on_nonstandard_port() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read()
    probe.tls.return_value = tls(True, version="TLSv1.2", cipher="AES")
    probe.http.return_value = read(b"HTTP/1.0 302 Found\r\nServer: envoy/1.0\r\n\r\n")

    result = asyncio.run(
        engine(probe).fingerprint_port(
            address="10.0.0.1", port=10443, hostname=None
        )
    )

    assert result.service is Service.HTTPS
    assert result.encrypted is True
    assert result.metadata["tls_version"] == "TLSv1.2"
    assert [item.source.value for item in result.evidence] == [
        "tls_handshake",
        "http_response",
    ]
    assert probe.http.await_args.kwargs["use_tls"] is True
    assert probe.http.await_args.kwargs["host_header"] == "10.0.0.1"


@pytest.mark.parametrize(
    ("passive", "tls_result", "http_results", "expected_error"),
    [
        (read(), tls(False), [read(), read()], None),
        (read(b"\x00\xffbinary"), tls(False), [read(), read()], None),
        (
            read(error="passive failed"),
            tls(False, error="tls failed"),
            [read(error="head failed"), read(error="get failed")],
            "get failed",
        ),
    ],
    ids=["no-data", "binary", "errors"],
)
def test_engine_returns_unknown_for_unrecognized_results(
    passive: ReadProbeResult,
    tls_result: TLSProbeResult,
    http_results: list[ReadProbeResult],
    expected_error: str | None,
) -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = passive
    probe.tls.return_value = tls_result
    probe.http.side_effect = http_results

    result = asyncio.run(
        engine(probe).fingerprint_port(
            address="10.0.0.1", port=12345, hostname=None
        )
    )

    assert result.service is Service.UNKNOWN
    assert result.error == expected_error
    assert result.evidence
    assert all(len(item.raw_preview or "") <= 512 for item in result.evidence)


def test_valid_head_response_stops_without_get_or_tls_on_http_hint() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read()
    probe.http.return_value = read(b"HTTP/1.1 200 OK\r\n\r\n")

    result = asyncio.run(
        engine(probe).fingerprint_port(address="10.0.0.1", port=8080, hostname=None)
    )

    assert result.service is Service.HTTP
    assert probe.http.await_count == 1
    assert probe.http.await_args.kwargs["method"] == "HEAD"
    probe.tls.assert_not_awaited()


def test_invalid_head_uses_one_bounded_get_fallback_then_stops() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read()
    probe.http.side_effect = [
        read(b"not-http\r\n\r\n"),
        read(b"HTTP/1.1 200 OK\r\nServer: fallback\r\n\r\n"),
    ]

    result = asyncio.run(
        engine(probe).fingerprint_port(address="10.0.0.1", port=80, hostname=None)
    )

    assert result.service is Service.HTTP
    assert probe.http.await_count == 2
    assert [item.kwargs["method"] for item in probe.http.await_args_list] == [
        "HEAD",
        "GET",
    ]
    probe.tls.assert_not_awaited()


def test_max_active_probe_count_is_respected_after_passive_probe() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read()
    probe.tls.return_value = tls(False)
    probe.http.return_value = read()

    result = asyncio.run(
        engine(probe, max_probes=1).fingerprint_port(
            address="10.0.0.1", port=12345, hostname=None
        )
    )

    assert result.service is Service.UNKNOWN
    probe.tls.assert_awaited_once()
    probe.http.assert_not_awaited()


def test_fingerprint_ports_only_processes_open_results_and_preserves_order() -> None:
    probe = AsyncMock()
    probe.passive_banner.return_value = read(b"SSH-2.0-test\r\n")
    ports = (
        port(81, PortState.CLOSED),
        port(22),
        port(82, PortState.FILTERED),
        port(2222),
        port(83, PortState.ERROR),
    )

    results = asyncio.run(
        engine(probe).fingerprint_ports(
            address="10.0.0.1", hostname=None, ports=ports
        )
    )

    assert [item.port for item in results] == [81, 22, 82, 2222, 83]
    assert [item.fingerprint is not None for item in results] == [
        False,
        True,
        False,
        True,
        False,
    ]
    assert probe.passive_banner.await_args_list == [
        call("10.0.0.1", 22),
        call("10.0.0.1", 2222),
    ]


def test_global_fingerprint_concurrency_is_shared_and_deterministic() -> None:
    active = 0
    maximum = 0
    two_started = asyncio.Event()
    release = asyncio.Event()

    async def passive(_address: str, _port: int) -> ReadProbeResult:
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        if active == 2:
            two_started.set()
        try:
            await release.wait()
            return read(b"SSH-2.0-test\r\n")
        finally:
            active -= 1

    probe = AsyncMock()
    probe.passive_banner.side_effect = passive
    fingerprint_engine = engine(probe, concurrency=2)

    async def exercise() -> tuple[tuple[PortResult, ...], tuple[PortResult, ...]]:
        first = asyncio.create_task(
            fingerprint_engine.fingerprint_ports(
                address="10.0.0.1", hostname=None, ports=(port(1), port(2), port(3))
            )
        )
        second = asyncio.create_task(
            fingerprint_engine.fingerprint_ports(
                address="10.0.0.2", hostname=None, ports=(port(4), port(5), port(6))
            )
        )
        await asyncio.wait_for(two_started.wait(), timeout=1)
        await asyncio.sleep(0)
        assert maximum == 2
        release.set()
        return await asyncio.gather(first, second)

    first, second = asyncio.run(exercise())

    assert maximum == 2
    assert [item.port for item in first] == [1, 2, 3]
    assert [item.port for item in second] == [4, 5, 6]
