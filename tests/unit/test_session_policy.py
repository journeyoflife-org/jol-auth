"""Tests for session policy — idle and absolute timeout checks."""

from datetime import UTC, datetime, timedelta

from app.core.session_policy import SessionPolicy


class TestSessionPolicy:
    def test_idle_not_expired(self) -> None:
        policy = SessionPolicy(idle_timeout=timedelta(minutes=30))
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        last_activity = datetime(2026, 7, 18, 11, 45, tzinfo=UTC)
        assert policy.is_idle_expired(last_activity, now) is False

    def test_idle_expired(self) -> None:
        policy = SessionPolicy(idle_timeout=timedelta(minutes=30))
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        last_activity = datetime(2026, 7, 18, 11, 0, tzinfo=UTC)
        assert policy.is_idle_expired(last_activity, now) is True

    def test_absolute_not_expired(self) -> None:
        policy = SessionPolicy(absolute_timeout=timedelta(hours=24))
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        created_at = datetime(2026, 7, 17, 13, 0, tzinfo=UTC)
        assert policy.is_absolute_expired(created_at, now) is False

    def test_absolute_expired(self) -> None:
        policy = SessionPolicy(absolute_timeout=timedelta(hours=24))
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        created_at = datetime(2026, 7, 17, 11, 0, tzinfo=UTC)
        assert policy.is_absolute_expired(created_at, now) is True
