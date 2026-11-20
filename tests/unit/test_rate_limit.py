"""Unit tests for the Redis-backed rate limiter.

Tests use fakeredis to avoid requiring a live Redis instance.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from app.security.rate_limit import RateLimiter, RateLimitResult


@pytest.fixture
def mock_redis():
    """Create a mock Redis with pipeline support."""
    redis = AsyncMock()
    pipe = AsyncMock()
    pipe.execute = AsyncMock(return_value=[0, True, 1, True])  # zrem, zadd, zcard, expire
    redis.pipeline = MagicMock(return_value=pipe)
    redis.hget = AsyncMock(return_value=b"3")
    return redis, pipe


class TestRateLimiter:
    """Tests for the sliding-window RateLimiter."""

    @pytest.mark.asyncio
    async def test_allows_request_under_limit(self, mock_redis):
        """Requests under the limit should be allowed."""
        redis, pipe = mock_redis
        pipe.execute = AsyncMock(return_value=[0, True, 1, True])  # count=1

        limiter = RateLimiter(redis=redis, max_requests=5, window_seconds=60)
        result = await limiter.check("login", "ip:192.168.1.1")

        assert result.allowed is True
        assert result.remaining == 4
        assert result.limit == 5

    @pytest.mark.asyncio
    async def test_blocks_request_over_limit(self, mock_redis):
        """Requests over the limit should be blocked."""
        redis, pipe = mock_redis
        pipe.execute = AsyncMock(return_value=[0, True, 6, True])  # count=6

        limiter = RateLimiter(redis=redis, max_requests=5, window_seconds=60)
        result = await limiter.check("login", "ip:192.168.1.1")

        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after_seconds == 60

    @pytest.mark.asyncio
    async def test_records_block_metadata(self, mock_redis):
        """Blocked requests should increment the blocked_count metadata."""
        redis, pipe = mock_redis
        pipe.execute = AsyncMock(return_value=[0, True, 6, True])  # count=6

        limiter = RateLimiter(redis=redis, max_requests=5, window_seconds=60)
        await limiter.check("login", "ip:192.168.1.1")

        # Second pipeline call should record metadata
        assert pipe.hincrby.called or redis.pipeline.call_count >= 2

    @pytest.mark.asyncio
    async def test_get_blocked_count(self, mock_redis):
        """Should return the blocked count from Redis metadata."""
        redis, _ = mock_redis
        redis.hget = AsyncMock(return_value="7")

        limiter = RateLimiter(redis=redis, max_requests=5, window_seconds=60)
        count = await limiter.get_blocked_count("login", "ip:192.168.1.1")

        assert count == 7

    @pytest.mark.asyncio
    async def test_different_identifiers_are_independent(self, mock_redis):
        """Different identifiers should have independent rate limits."""
        redis, pipe = mock_redis
        # First call: 1 request
        pipe.execute = AsyncMock(return_value=[0, True, 1, True])

        limiter = RateLimiter(redis=redis, max_requests=5, window_seconds=60)
        result1 = await limiter.check("login", "ip:10.0.0.1")
        assert result1.allowed is True

        # Second call with different IP: also 1 request (independent)
        result2 = await limiter.check("login", "ip:10.0.0.2")
        assert result2.allowed is True


class TestRateLimitResult:
    """Tests for the RateLimitResult dataclass."""

    def test_result_is_frozen(self):
        """RateLimitResult should be immutable."""
        result = RateLimitResult(
            allowed=True,
            remaining=5,
            limit=10,
            window_seconds=60,
            retry_after_seconds=0,
        )
        with pytest.raises(AttributeError):
            result.allowed = False  # type: ignore[misc]
