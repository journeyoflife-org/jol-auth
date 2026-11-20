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

"""Session service — creation, validation, and revocation of user sessions.

Sessions are tenant-scoped and enforce both idle timeout and absolute timeout.
Revocation is immediate and emits an audit event.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.session_policy import SessionPolicy
from app.db.repositories.session_repo import SessionRepository
from app.models.session import Session


class SessionService:
    """Manages server-side sessions within a tenant boundary."""

    def __init__(self, db: AsyncSession) -> None:
        self._repo = SessionRepository(db)
        self._policy = SessionPolicy()

    async def create_session(
        self,
        tenant_id: UUID,
        user_id: UUID,
        ip: str | None = None,
        ua: str | None = None,
    ) -> Session:
        """Create a new session for an authenticated user."""
        now = datetime.now(tz=UTC)
        session = Session(
            tenant_id=tenant_id,
            user_id=user_id,
            ip_address=ip,
            user_agent=ua,
            last_activity=now,
            expires_at=now + self._policy.absolute_timeout,
            revoked=False,
        )
        return await self._repo.create(session)

    async def validate_session(self, session_id: UUID, tenant_id: UUID) -> Session | None:
        """Check whether a session is still valid.

        Returns the session if valid, ``None`` if expired, revoked, or not found.
        Checks: revocation status, idle timeout, absolute timeout.
        """
        from sqlalchemy import select

        stmt = select(Session).where(
            Session.id == session_id,
            Session.tenant_id == tenant_id,
        )
        result = await self._repo._db.execute(stmt)
        session = result.scalar_one_or_none()

        if session is None or session.revoked:
            return None

        now = datetime.now(tz=UTC)
        if self._policy.is_idle_expired(session.last_activity, now):
            return None
        if self._policy.is_absolute_expired(session.created_at, now):
            return None

        # Update last activity
        session.last_activity = now
        await self._repo._db.commit()
        return session

    async def get_active_sessions(self, tenant_id: UUID, user_id: UUID) -> list[Session]:
        """Return all non-revoked sessions for a user within a tenant."""
        return await self._repo.get_active_for_user(user_id, tenant_id)

    async def revoke_session(self, session_id: UUID, tenant_id: UUID) -> None:
        """Revoke a specific session. Tenant-scoped."""
        await self._repo.revoke(session_id, tenant_id)
