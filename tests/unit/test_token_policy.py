"""Tests for token policy — TTL and expiry calculations."""

from datetime import UTC, datetime, timedelta

from app.core.token_policy import TokenPolicy


class TestTokenPolicy:
    def test_default_access_token_ttl(self) -> None:
        policy = TokenPolicy()
        assert policy.access_token_ttl == timedelta(minutes=15)

    def test_default_refresh_token_ttl(self) -> None:
        policy = TokenPolicy()
        assert policy.refresh_token_ttl == timedelta(days=30)

    def test_access_token_expiry(self) -> None:
        policy = TokenPolicy(access_token_ttl=timedelta(minutes=10))
        now = datetime(2026, 1, 1, tzinfo=UTC)
        expiry = policy.access_token_expiry(now)
        assert expiry == datetime(2026, 1, 1, 0, 10, tzinfo=UTC)

    def test_refresh_token_expiry(self) -> None:
        policy = TokenPolicy(refresh_token_ttl=timedelta(days=7))
        now = datetime(2026, 1, 1, tzinfo=UTC)
        expiry = policy.refresh_token_expiry(now)
        assert expiry == datetime(2026, 1, 8, tzinfo=UTC)

    def test_authorization_code_expiry(self) -> None:
        policy = TokenPolicy(authorization_code_ttl=timedelta(minutes=2))
        now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
        expiry = policy.authorization_code_expiry(now)
        assert expiry == datetime(2026, 6, 15, 12, 2, tzinfo=UTC)
