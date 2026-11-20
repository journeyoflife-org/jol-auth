"""Session repository — CRUD operations for the sessions table."""

from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.session import Session


class SessionRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_active_for_user(self, user_id: UUID, tenant_id: UUID) -> list[Session]:
        stmt = (
            select(Session)
            .where(Session.user_id == user_id, Session.tenant_id == tenant_id, Session.revoked.is_(False))
            .order_by(Session.last_activity.desc())
        )
        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def revoke(self, session_id: UUID, tenant_id: UUID) -> None:
        stmt = update(Session).where(Session.id == session_id, Session.tenant_id == tenant_id).values(revoked=True)
        await self._db.execute(stmt)
        await self._db.commit()

    async def create(self, session: Session) -> Session:
        self._db.add(session)
        await self._db.commit()
        await self._db.refresh(session)
        return session
