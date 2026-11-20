"""Session policy — idle and absolute timeout management."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass
class SessionPolicy:
    """Configuration for session lifetimes."""

    idle_timeout: timedelta = timedelta(minutes=30)
    absolute_timeout: timedelta = timedelta(hours=24)

    def is_idle_expired(self, last_activity: datetime, now: datetime | None = None) -> bool:
        """Check whether a session has exceeded the idle timeout."""
        return (now or datetime.now(tz=UTC)) - last_activity > self.idle_timeout

    def is_absolute_expired(self, created_at: datetime, now: datetime | None = None) -> bool:
        """Check whether a session has exceeded the absolute timeout."""
        return (now or datetime.now(tz=UTC)) - created_at > self.absolute_timeout
