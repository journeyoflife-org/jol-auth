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

"""Audit event helpers — structured event creation for compliance logging."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4


class AuditAction(StrEnum):
    """Standard audit event actions."""

    LOGIN_SUCCESS = "login.success"
    LOGIN_FAILURE = "login.failure"
    TOKEN_ISSUED = "token.issued"  # noqa: S105
    TOKEN_REVOKED = "token.revoked"  # noqa: S105
    TOKEN_REFRESHED = "token.refreshed"  # noqa: S105
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    MFA_ENROLLED = "mfa.enrolled"
    MFA_REMOVED = "mfa.removed"
    ADMIN_ACTION = "admin.action"


@dataclass
class AuditEvent:
    """Structured audit event for compliance and forensics."""

    action: AuditAction
    tenant_id: UUID
    actor_id: UUID | None = None
    target_id: UUID | None = None
    details: dict[str, Any] = field(default_factory=dict)
    event_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    ip_address: str | None = None
    user_agent: str | None = None
