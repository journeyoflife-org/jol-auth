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
