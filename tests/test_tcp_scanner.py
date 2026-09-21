import asyncio
import errno
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rcscan.network.errors import classify_connection_error
from rcscan.network.models import PortState
from rcscan.network.tcp_scanner import TCPScanner


def scanner_for(connector, *, concurrency: int = 2, retries: int = 0) -> TCPScanner:
    return TCPScanner(
        timeout_seconds=0.1,
        concurrency=concurrency,
        retries=retries,
        connector=connector,
    )


def windows_error(code: int) -> OSError:
    error = OSError(f"simulated WinError {code}")
    error.winerror = code
    return error


def test_open_result_records_latency_and_closes_writer() -> None:
    writer = MagicMock()
    writer.wait_closed = AsyncMock()
    connector = AsyncMock(return_value=(MagicMock(), writer))
    scanner = scanner_for(connector)

    with patch(
        "rcscan.network.tcp_scanner.perf_counter",
        side_effect=(0.0, 10.0, 10.025),
    ):
        result = asyncio.run(scanner.scan_port("10.0.0.1", 443))

    assert result.state is PortState.OPEN
    assert result.latency_ms == pytest.approx(25.0)
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


@pytest.mark.parametrize(
    ("error", "state"),
    [
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), PortState.CLOSED),
        (TimeoutError(), PortState.FILTERED),
        (OSError(errno.EHOSTUNREACH, "unreachable"), PortState.ERROR),
        (ValueError("unexpected"), PortState.ERROR),
    ],
)
def test_connection_outcomes_are_classified(error: Exception, state: PortState) -> None:
    connector = AsyncMock(side_effect=error)

    result = asyncio.run(scanner_for(connector).scan_port("10.0.0.1", 80))

    assert result.state is state
    assert result.latency_ms >= 0


@pytest.mark.parametrize(
    "error",
    [TimeoutError(), OSError(errno.ECONNRESET, "reset"), OSError(10054, "reset")],
)
def test_retries_only_timeout_and_transient_errors(error: Exception) -> None:
    writer = MagicMock()
    writer.wait_closed = AsyncMock()
    connector = AsyncMock(
        side_effect=[error, (MagicMock(), writer)]
    )

    result = asyncio.run(scanner_for(connector, retries=1).scan_port("10.0.0.1", 80))

    assert result.state is PortState.OPEN
    assert connector.await_count == 2


@pytest.mark.parametrize(
    "outcome",
    [
        ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
        ValueError("permanent"),
    ],
)
def test_closed_and_nontransient_error_are_not_retried(outcome: Exception) -> None:
    connector = AsyncMock(side_effect=outcome)

    asyncio.run(scanner_for(connector, retries=3).scan_port("10.0.0.1", 80))

    assert connector.await_count == 1


def test_explicit_unreachable_error_is_not_retried() -> None:
    connector = AsyncMock(side_effect=OSError(errno.EHOSTUNREACH, "unreachable"))

    result = asyncio.run(
        scanner_for(connector, retries=3).scan_port("10.0.0.1", 80)
    )

    assert result.state is PortState.ERROR
    assert connector.await_count == 1


def test_open_port_is_not_retried() -> None:
    writer = MagicMock()
    writer.wait_closed = AsyncMock()
    connector = AsyncMock(return_value=(MagicMock(), writer))

    result = asyncio.run(
        scanner_for(connector, retries=3).scan_port("10.0.0.1", 80)
    )

    assert result.state is PortState.OPEN
    assert connector.await_count == 1


def test_global_configured_concurrency_never_exceeds_five() -> None:
    active = 0
    maximum_active = 0
    release = asyncio.Event()
    five_started = asyncio.Event()

    async def connector(_host: str, _port: int):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        if active == 5:
            five_started.set()
        try:
            await release.wait()
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        finally:
            active -= 1

    async def exercise() -> tuple:
        scanner = scanner_for(connector, concurrency=5)
        first = asyncio.create_task(scanner.scan_ports("10.0.0.1", range(1, 9)))
        second = asyncio.create_task(scanner.scan_ports("10.0.0.2", range(9, 17)))
        await asyncio.wait_for(five_started.wait(), timeout=1)
        await asyncio.sleep(0)
        assert maximum_active == 5
        release.set()
        return await asyncio.gather(first, second)

    results = asyncio.run(exercise())

    assert maximum_active == 5
    assert sum(len(group) for group in results) == 16


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
        OSError(errno.ECONNREFUSED, "refused"),
        windows_error(10061),
        windows_error(1225),
    ],
)
def test_refusal_variants_are_closed(error: OSError) -> None:
    classified = classify_connection_error(error)

    assert classified.state is PortState.CLOSED
    assert classified.retryable is False


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError(),
        vars(asyncio)["TimeoutError"](),
        windows_error(10060),
    ],
    ids=["builtin-timeout", "asyncio-timeout", "wsa-timeout"],
)
def test_timeout_variants_are_filtered(error: OSError) -> None:
    classified = classify_connection_error(error)

    assert classified.state is PortState.FILTERED
    assert classified.retryable is True


@pytest.mark.parametrize("code", [10051, 10065])
def test_windows_unreachable_variants_are_errors(code: int) -> None:
    classified = classify_connection_error(windows_error(code))

    assert classified.state is PortState.ERROR
    assert classified.explicitly_unreachable is True
    assert classified.retryable is False


def test_windows_refusal_is_not_retried() -> None:
    connector = AsyncMock(side_effect=windows_error(10061))

    result = asyncio.run(
        scanner_for(connector, retries=3).scan_port("127.0.0.1", 54321)
    )

    assert result.state is PortState.CLOSED
    assert connector.await_count == 1


def test_persistent_timeout_obeys_configured_retry_count() -> None:
    connector = AsyncMock(side_effect=TimeoutError())

    result = asyncio.run(
        scanner_for(connector, retries=2).scan_port("127.0.0.1", 54321)
    )

    assert result.state is PortState.FILTERED
    assert connector.await_count == 3


def test_debug_log_contains_sanitized_attempt_diagnostics() -> None:
    connector = AsyncMock(side_effect=windows_error(10061))
    scanner = scanner_for(connector, retries=1)

    with patch.object(scanner._logger, "debug") as debug:
        asyncio.run(
            scanner.scan_port("127.0.0.1", 54321)
        )

    template, *arguments = debug.call_args.args
    message = template % tuple(arguments)
    assert "exception=OSError" in message
    assert "errno=None" in message
    assert "winerror=10061" in message
    assert "attempt=1/2" in message
    assert "elapsed_ms=" in message
    assert "classification=CLOSED" in message
    assert "will_retry=False" in message
