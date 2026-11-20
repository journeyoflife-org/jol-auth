"""Audit service — structured event emission and query for compliance.

Persists audit events to the ``audit_events`` table (append-only).
All queries are tenant-scoped.
"""

import json
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditEvent
from app.models.audit_event import AuditEventModel


class AuditService:
    """Append-only audit log with tenant-scoped queries."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def emit(self, event: AuditEvent) -> None:
        """Persist an audit event to the database.

        The ``details`` dict is JSON-serialised into the ``Text`` column.
        """
        record = AuditEventModel(
            id=event.event_id,
            tenant_id=event.tenant_id,
            action=str(event.action),
            actor_id=event.actor_id,
            target_id=event.target_id,
            details=json.dumps(event.details) if event.details else None,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
        )
        self._db.add(record)
        await self._db.commit()

    async def query(self, tenant_id: UUID, action: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Query audit events for a tenant with optional action filter.

        Returns events in descending chronological order, capped at ``limit``.
        """
        stmt = (
            select(AuditEventModel)
            .where(AuditEventModel.tenant_id == tenant_id)
            .order_by(AuditEventModel.created_at.desc())
            .limit(limit)
        )
        if action:
            stmt = stmt.where(AuditEventModel.action == action)

        result = await self._db.execute(stmt)
        rows = result.scalars().all()

        return [
            {
                "id": str(row.id),
                "action": row.action,
                "actor_id": str(row.actor_id) if row.actor_id else None,
                "target_id": str(row.target_id) if row.target_id else None,
                "details": json.loads(row.details) if row.details else {},
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
