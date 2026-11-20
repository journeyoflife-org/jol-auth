# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
