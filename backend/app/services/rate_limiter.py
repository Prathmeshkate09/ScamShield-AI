from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from app.config import Settings
from app.core.errors import RateLimiterUnavailableError, RateLimitExceededError

logger = logging.getLogger(__name__)


class CounterStore(Protocol):
    async def eval(self, script: str, keys: list[str], args: list[str]) -> list[int]: ...

    async def ping(self) -> Any: ...


@dataclass(frozen=True)
class RateLimitDecision:
    remaining: int | None
    retry_after: int | None


class RateLimitService:
    _INCREMENT_WITH_TTL = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {current, redis.call('TTL', KEYS[1])}
"""

    def __init__(self, settings: Settings, client: CounterStore | None = None) -> None:
        self.settings = settings
        self.client = client
        self.available = not settings.rate_limit_enabled
        if self.client is None and settings.rate_limit_enabled and settings.rate_limiter_configured:
            from upstash_redis.asyncio import Redis

            self.client = Redis(url=settings.upstash_redis_rest_url or "", token=settings.upstash_redis_rest_token or "")

    @property
    def state(self) -> str:
        if not self.settings.rate_limit_enabled:
            return "disabled"
        return "ready" if self.available else "degraded"

    async def initialize(self) -> None:
        if not self.settings.rate_limit_enabled:
            return
        if self.client is None:
            self.available = False
            logger.error("rate_limiter.not_configured")
            return
        try:
            await self.client.ping()
        except Exception:
            self.available = False
            logger.exception("rate_limiter.unavailable")
            return
        self.available = True

    async def enforce_health(self, ip_address: str) -> RateLimitDecision:
        return await self._enforce("health", ip_address, self.settings.rate_limit_health_per_window)

    async def enforce_user(self, user_id: UUID) -> RateLimitDecision:
        return await self._enforce("user", str(user_id), self.settings.rate_limit_user_per_window)

    async def enforce_scan(self, user_id: UUID, scan_type: str) -> RateLimitDecision:
        limit = self.settings.rate_limit_image_per_window if scan_type == "image" else self.settings.rate_limit_scan_per_window
        return await self._enforce(f"scan:{scan_type}", str(user_id), limit)

    async def _enforce(self, category: str, identity: str, limit: int) -> RateLimitDecision:
        if not self.settings.rate_limit_enabled:
            return RateLimitDecision(remaining=None, retry_after=None)
        if self.client is None or not self.available:
            raise RateLimiterUnavailableError()

        window = int(time.time() // self.settings.rate_limit_window_seconds)
        key = f"scamshield:rate:{category}:{identity}:{window}"
        try:
            result = await self.client.eval(self._INCREMENT_WITH_TTL, [key], [str(self.settings.rate_limit_window_seconds)])
            count = int(result[0])
            retry_after = max(int(result[1]), 1)
        except Exception as error:
            self.available = False
            logger.exception("rate_limiter.command_failed", extra={"category": category})
            raise RateLimiterUnavailableError() from error

        if count > limit:
            raise RateLimitExceededError(retry_after)
        return RateLimitDecision(remaining=max(limit - count, 0), retry_after=retry_after)
