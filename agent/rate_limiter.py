import asyncio
import time


class AsyncRateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1.0 / max(requests_per_second, 0.1)
        self._lock = asyncio.Lock()
        self._last_time = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            sleep_for = self.interval - (now - self._last_time)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last_time = time.monotonic()
