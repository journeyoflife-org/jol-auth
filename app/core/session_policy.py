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
