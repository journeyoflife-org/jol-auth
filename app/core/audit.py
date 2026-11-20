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
