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
