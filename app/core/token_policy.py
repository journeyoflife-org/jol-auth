"""Token policy — TTL, rotation, and revocation rules for OAuth tokens."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass
class TokenPolicy:
    """Configuration for token lifetimes and rotation behaviour."""

    access_token_ttl: timedelta = timedelta(minutes=15)
    refresh_token_ttl: timedelta = timedelta(days=30)
    authorization_code_ttl: timedelta = timedelta(minutes=5)
    refresh_rotation_enabled: bool = True

    def access_token_expiry(self, now: datetime | None = None) -> datetime:
        """Calculate the expiry timestamp for a new access token."""
        return (now or datetime.now(tz=UTC)) + self.access_token_ttl

    def refresh_token_expiry(self, now: datetime | None = None) -> datetime:
        """Calculate the expiry timestamp for a new refresh token."""
        return (now or datetime.now(tz=UTC)) + self.refresh_token_ttl

    def authorization_code_expiry(self, now: datetime | None = None) -> datetime:
        """Calculate the expiry timestamp for an authorization code."""
        return (now or datetime.now(tz=UTC)) + self.authorization_code_ttl
