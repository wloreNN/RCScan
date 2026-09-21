"""Cancellation-aware, coordinated per-origin HTTP throttling."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import monotonic

from rcscan.web.request_context import normalized_origin

_LOGGER = logging.getLogger(__name__)
Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]
WallClock = Callable[[], datetime]


@dataclass(slots=True)
class _OriginState:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    next_allowed: float = 0.0
    transient_events: int = 0


class OriginThrottleCoordinator:
    """Coordinate minimum intervals and server-directed backoff by web origin."""

    def __init__(
        self,
        *,
        min_request_interval_seconds: float,
        max_retry_after_seconds: float,
        max_transient_retries: int,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = monotonic,
        wall_clock: WallClock | None = None,
    ) -> None:
        self.min_request_interval_seconds = min_request_interval_seconds
        self.max_retry_after_seconds = max_retry_after_seconds
        self.max_transient_retries = max_transient_retries
        self._sleep = sleep
        self._clock = clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._states: dict[str, _OriginState] = {}
        self.throttling_events = 0
        self.requests_delayed = 0

    async def wait(self, url: str) -> None:
        origin = normalized_origin(url)
        if origin is None:
            return
        state = self._states.setdefault(origin, _OriginState())
        async with state.lock:
            now = self._clock()
            scheduled = max(now, state.next_allowed)
            delay = max(0.0, scheduled - now)
            state.next_allowed = scheduled + self.min_request_interval_seconds
        if delay > 0:
            self.requests_delayed += 1
            await self._sleep(delay)

    async def backoff(
        self,
        url: str,
        *,
        status_code: int | None,
        retry_after: str | None,
        retry_number: int,
    ) -> float:
        origin = normalized_origin(url)
        if origin is None:
            return 0.0
        state = self._states.setdefault(origin, _OriginState())
        parsed = parse_retry_after(
            retry_after,
            now=self._wall_clock(),
        )
        exponential: float = min(
            0.25 * float(2 ** max(retry_number - 1, 0)),
            self.max_retry_after_seconds,
        )
        delay: float = min(
            max(parsed if parsed is not None else 0.0, exponential),
            self.max_retry_after_seconds,
        )
        async with state.lock:
            state.transient_events += 1
            state.next_allowed = max(state.next_allowed, self._clock() + delay)
        self.throttling_events += 1
        _LOGGER.debug(
            "HTTP throttling detected origin=%s status=%s retry=%d wait_seconds=%.3f",
            origin,
            status_code if status_code is not None else "temporary-failure",
            retry_number,
            delay,
        )
        return delay

    def note_success(self, url: str) -> None:
        origin = normalized_origin(url)
        state = self._states.get(origin or "")
        if state is not None:
            state.transient_events = 0


def parse_retry_after(value: str | None, *, now: datetime) -> float | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped.isdecimal():
        return float(int(stripped))
    try:
        parsed = parsedate_to_datetime(stripped)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (parsed - now).total_seconds())
