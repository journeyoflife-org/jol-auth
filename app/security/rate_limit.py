"""Rate limiter — sliding window rate limiting backed by Redis.

Uses Redis sorted sets (ZSETs) for an accurate sliding window algorithm.
Each request is recorded as a ZSET member with its timestamp as the score.
Before allowing a request, expired members are evicted and the remaining
count is checked against the configured maximum.

Redis key schema:
    ratelimit:{scope}:{identifier}    → ZSET of {unique_id → timestamp}
    ratelimit:{scope}:{identifier}:meta → HASH with {blocked_count, last_blocked_at}

TTL: Keys expire after 2x the window to allow stale cleanup.
"""

import time
import uuid
from dataclasses import dataclass

import redis.asyncio as aioredis

from app.config import settings


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate-limit check."""

    allowed: bool
    remaining: int
    limit: int
    window_seconds: int
    retry_after_seconds: int


class RateLimiter:
    """Sliding-window rate limiter backed by Redis sorted sets.

    Thread-safe and async.  A single instance can be shared across
    requests because all state lives in Redis.
    """

    KEY_PREFIX = "ratelimit"
    TTL_MULTIPLIER = 2  # Keys expire after 2x window

    def __init__(
        self,
        redis: aioredis.Redis | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._redis = redis
        self._max_requests = max_requests
        self._window_seconds = window_seconds

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is not None:
            return self._redis
        # Lazy-init from settings — avoids connecting at import time
        self._redis = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        return self._redis

    async def check(self, scope: str, identifier: str) -> RateLimitResult:
        """Check whether a request is allowed under the rate limit.

        This is an atomic check-and-increment operation.  If the request
        is allowed, the counter is incremented immediately.

        Args:
            scope: Logical grouping (e.g. ``"login"``, ``"token"``, ``"api"``).
            identifier: The entity being limited (IP, user_id, client_id).

        Returns:
            RateLimitResult with the decision and metadata.
        """
        redis = await self._get_redis()
        now = time.time()
        window_start = now - self._window_seconds
        key = f"{self.KEY_PREFIX}:{scope}:{identifier}"

        # Generate a unique member ID (timestamp + uuid for sub-ms uniqueness)
        member = f"{now}:{uuid.uuid4()}"

        # Atomic pipeline: evict old entries, add new, count, set TTL
        pipe = redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)  # Evict expired
        pipe.zadd(key, {member: now})  # Add current request
        pipe.zcard(key)  # Count remaining
        pipe.expire(key, self._window_seconds * self.TTL_MULTIPLIER)
        results = await pipe.execute()

        count = results[2]
        allowed = count <= self._max_requests
        remaining = max(0, self._max_requests - count)
        retry_after = 0 if allowed else self._window_seconds

        if not allowed:
            # Record block metadata for monitoring
            meta_key = f"{key}:meta"
            pipe = redis.pipeline()
            pipe.hincrby(meta_key, "blocked_count", 1)
            pipe.hset(meta_key, "last_blocked_at", str(int(now)))
            pipe.expire(meta_key, self._window_seconds * self.TTL_MULTIPLIER)
            await pipe.execute()

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            limit=self._max_requests,
            window_seconds=self._window_seconds,
            retry_after_seconds=retry_after,
        )

    async def get_blocked_count(self, scope: str, identifier: str) -> int:
        """Return the number of blocked requests for a scope/identifier."""
        redis = await self._get_redis()
        meta_key = f"{self.KEY_PREFIX}:{scope}:{identifier}:meta"
        count = await redis.hget(meta_key, "blocked_count")
        return int(count) if count else 0


# ---------------------------------------------------------------------------
# Pre-configured limiters for different endpoint categories
# ---------------------------------------------------------------------------


def login_limiter(redis: aioredis.Redis | None = None) -> RateLimiter:
    """Rate limiter for login/authentication endpoints."""
    return RateLimiter(
        redis=redis,
        max_requests=settings.rate_limit_login_attempts,
        window_seconds=300,  # 5 attempts per 5 minutes
    )


def token_limiter(redis: aioredis.Redis | None = None) -> RateLimiter:
    """Rate limiter for token endpoint (prevent token flooding)."""
    return RateLimiter(
        redis=redis,
        max_requests=settings.rate_limit_requests_per_minute,
        window_seconds=60,
    )


def api_limiter(redis: aioredis.Redis | None = None) -> RateLimiter:
    """General API rate limiter."""
    return RateLimiter(
        redis=redis,
        max_requests=settings.rate_limit_requests_per_minute,
        window_seconds=60,
    )


def mfa_limiter(redis: aioredis.Redis | None = None) -> RateLimiter:
    """Rate limiter for MFA verification attempts."""
    return RateLimiter(
        redis=redis,
        max_requests=10,  # 10 MFA attempts per 5 minutes
        window_seconds=300,
    )
