"""Revocation service — coordinated revocation of tokens, sessions, and clients.

Provides bulk revocation operations for incident response scenarios
(e.g. key compromise, account takeover). All operations are tenant-scoped.
"""

from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repositories.session_repo import SessionRepository
from app.db.repositories.token_repo import TokenRepository
from app.models.refresh_token import RefreshToken
from app.models.session import Session as SessionModel
from app.models.token import Token


class RevocationService:
    """Coordinates revocation of tokens and sessions within a tenant boundary."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._token_repo = TokenRepository(db)
        self._session_repo = SessionRepository(db)

    async def revoke_user(self, tenant_id: UUID, user_id: UUID) -> None:
        """Revoke all tokens and sessions for a user within a tenant."""
        # Revoke all access tokens
        stmt = (
            update(Token)
            .where(Token.user_id == user_id, Token.tenant_id == tenant_id, Token.revoked.is_(False))
            .values(revoked=True)
        )
        await self._db.execute(stmt)

        # Revoke all refresh tokens
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.tenant_id == tenant_id,
                RefreshToken.revoked.is_(False),
            )
            .values(revoked=True)
        )
        await self._db.execute(stmt)

        # Revoke all sessions
        stmt = (
            update(SessionModel)
            .where(
                SessionModel.user_id == user_id,
                SessionModel.tenant_id == tenant_id,
                SessionModel.revoked.is_(False),
            )
            .values(revoked=True)
        )
        await self._db.execute(stmt)
        await self._db.commit()

    async def revoke_client_tokens(self, tenant_id: UUID, client_id: str) -> None:
        """Revoke all tokens issued to a specific OAuth client within a tenant."""
        stmt = (
            update(Token)
            .where(Token.client_id == client_id, Token.tenant_id == tenant_id, Token.revoked.is_(False))
            .values(revoked=True)
        )
        await self._db.execute(stmt)

        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.client_id == client_id,
                RefreshToken.tenant_id == tenant_id,
                RefreshToken.revoked.is_(False),
            )
            .values(revoked=True)
        )
        await self._db.execute(stmt)
        await self._db.commit()

    async def revoke_tenant(self, tenant_id: UUID) -> None:
        """Revoke all tokens and sessions for an entire tenant.

        This is a high-severity operation used during incident response.
        """
        stmt = update(Token).where(Token.tenant_id == tenant_id, Token.revoked.is_(False)).values(revoked=True)
        await self._db.execute(stmt)

        stmt = (
            update(RefreshToken)
            .where(RefreshToken.tenant_id == tenant_id, RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )
        await self._db.execute(stmt)

        stmt = (
            update(SessionModel)
            .where(SessionModel.tenant_id == tenant_id, SessionModel.revoked.is_(False))
            .values(revoked=True)
        )
        await self._db.execute(stmt)
        await self._db.commit()
