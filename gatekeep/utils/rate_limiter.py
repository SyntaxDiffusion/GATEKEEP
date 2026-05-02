"""
Async rate limiter for GATEKEEP.

Provides a simple sliding-window rate limiter that can be used to
throttle API calls (e.g. to the Anthropic API) or any other
resource that needs request-rate governance.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class AsyncRateLimiter:
    """
    Sliding-window async rate limiter.

    Tracks call timestamps and blocks callers via asyncio.sleep()
    when the rate limit would be exceeded.

    Usage:
        limiter = AsyncRateLimiter(max_calls=20, period_seconds=60)

        async def make_api_call():
            await limiter.acquire()
            # ... perform the rate-limited operation ...
    """

    def __init__(self, max_calls: int, period_seconds: float) -> None:
        """
        Initialize the rate limiter.

        Args:
            max_calls: Maximum number of calls allowed within the period.
            period_seconds: Length of the sliding window in seconds.

        Raises:
            ValueError: If max_calls < 1 or period_seconds <= 0.
        """
        if max_calls < 1:
            raise ValueError(f"max_calls must be >= 1, got {max_calls}")
        if period_seconds <= 0:
            raise ValueError(f"period_seconds must be > 0, got {period_seconds}")

        self._max_calls = max_calls
        self._period = period_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    @property
    def max_calls(self) -> int:
        """Maximum calls allowed per period."""
        return self._max_calls

    @property
    def period_seconds(self) -> float:
        """Sliding window duration in seconds."""
        return self._period

    def _prune_expired(self, now: float) -> None:
        """Remove timestamps that have fallen outside the sliding window."""
        cutoff = now - self._period
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

    @property
    def available_calls(self) -> int:
        """Number of calls available right now without waiting."""
        self._prune_expired(time.monotonic())
        return max(0, self._max_calls - len(self._timestamps))

    async def acquire(self) -> None:
        """
        Acquire permission to make a rate-limited call.

        If the rate limit is currently exhausted, this coroutine sleeps
        until the oldest tracked call expires from the window, then
        records the new call timestamp.
        """
        async with self._lock:
            now = time.monotonic()
            self._prune_expired(now)

            if len(self._timestamps) >= self._max_calls:
                # Calculate how long to wait for the oldest entry to expire
                oldest = self._timestamps[0]
                wait_time = self._period - (now - oldest)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                # Re-check after sleeping
                now = time.monotonic()
                self._prune_expired(now)

            self._timestamps.append(time.monotonic())

    def reset(self) -> None:
        """Clear all tracked timestamps, resetting the limiter."""
        self._timestamps.clear()
