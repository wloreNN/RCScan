"""Bounded asynchronous TCP connect scanning."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from contextlib import suppress
from datetime import UTC, datetime
from time import perf_counter

from rcscan.network.errors import classify_connection_error
from rcscan.network.models import PortResult, PortState

ConnectCallable = Callable[
    [str, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]
PortCallback = Callable[[PortResult], None]


class TCPScanner:
    """Scan TCP ports while sharing one global connection semaphore."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        concurrency: int,
        retries: int,
        connector: ConnectCallable | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._concurrency = concurrency
        self._retries = retries
        self._connector: ConnectCallable = connector or asyncio.open_connection
        self._semaphore = asyncio.Semaphore(concurrency)
        self._logger = logging.getLogger(__name__)

    async def scan_port(
        self,
        host: str,
        port: int,
        *,
        timeout_seconds: float | None = None,
        retries: int | None = None,
    ) -> PortResult:
        """Return the final classified result for one host and TCP port."""
        attempt_limit = (self._retries if retries is None else retries) + 1
        timeout = self._timeout_seconds if timeout_seconds is None else timeout_seconds
        final_result: PortResult | None = None
        for attempt in range(attempt_limit):
            final_result, retryable = await self._attempt(
                host,
                port,
                timeout,
                attempt_number=attempt + 1,
                attempt_limit=attempt_limit,
            )
            if not retryable or attempt + 1 >= attempt_limit:
                return final_result
        if final_result is None:  # Defensive: attempt_limit is always at least one.
            raise RuntimeError("TCP scan produced no result")
        return final_result

    async def scan_ports(
        self,
        host: str,
        ports: Iterable[int],
        *,
        timeout_seconds: float | None = None,
        retries: int | None = None,
        on_result: PortCallback | None = None,
    ) -> tuple[PortResult, ...]:
        """Scan a port collection with a fixed-size worker pool."""
        queue: asyncio.Queue[int] = asyncio.Queue()
        for port in ports:
            queue.put_nowait(port)
        if queue.empty():
            return ()

        results: list[PortResult] = []

        async def worker() -> None:
            while True:
                try:
                    port = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    result = await self.scan_port(
                        host,
                        port,
                        timeout_seconds=timeout_seconds,
                        retries=retries,
                    )
                    results.append(result)
                    if on_result is not None:
                        on_result(result)
                finally:
                    queue.task_done()

        worker_count = min(self._concurrency, queue.qsize())
        async with asyncio.TaskGroup() as group:
            for _ in range(worker_count):
                group.create_task(worker())
        return tuple(sorted(results, key=lambda result: result.port))

    async def _attempt(
        self,
        host: str,
        port: int,
        timeout_seconds: float,
        *,
        attempt_number: int,
        attempt_limit: int,
    ) -> tuple[PortResult, bool]:
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            async with self._semaphore:
                started = perf_counter()
                async with asyncio.timeout(timeout_seconds):
                    _, writer = await self._connector(host, port)
                latency_ms = (perf_counter() - started) * 1_000
                return (
                    PortResult(
                        host=host,
                        port=port,
                        state=PortState.OPEN,
                        latency_ms=latency_ms,
                        timestamp=datetime.now(UTC),
                    ),
                    False,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            classified = classify_connection_error(exc)
            latency_ms = (perf_counter() - started) * 1_000
            self._logger.debug(
                "TCP attempt failed host=%s port=%d exception=%s errno=%s "
                "winerror=%s attempt=%d/%d elapsed_ms=%.2f classification=%s "
                "will_retry=%s",
                host,
                port,
                classified.exception_class,
                classified.errno_value,
                classified.winerror,
                attempt_number,
                attempt_limit,
                latency_ms,
                classified.state.value,
                classified.retryable and attempt_number < attempt_limit,
            )
            return (
                PortResult(
                    host=host,
                    port=port,
                    state=classified.state,
                    latency_ms=latency_ms,
                    error_code=classified.code,
                    error_message=classified.message,
                    timestamp=datetime.now(UTC),
                ),
                classified.retryable,
            )
        finally:
            if writer is not None:
                writer.close()
                try:
                    await _wait_for_writer_close(writer)
                except (ConnectionError, OSError):
                    self._logger.debug(
                        "Writer cleanup reported an error host=%s port=%d",
                        host,
                        port,
                    )


async def _wait_for_writer_close(writer: asyncio.StreamWriter) -> None:
    """Finish writer cleanup even when cancellation arrives during close."""
    close_task = asyncio.ensure_future(writer.wait_closed())
    try:
        await asyncio.shield(close_task)
    except asyncio.CancelledError:
        with suppress(ConnectionError, OSError):
            await close_task
        raise
