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
