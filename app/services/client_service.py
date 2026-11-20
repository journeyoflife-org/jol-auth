"""Client service — OAuth client registration, validation, and revocation.

All operations are tenant-scoped. Client secrets are hashed with
Argon2id before storage.
"""

import secrets
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, UnauthorizedError
from app.core.security import hash_password, verify_password
from app.db.repositories.client_repo import ClientRepository
from app.models.client import Client
from app.models.refresh_token import RefreshToken
from app.models.token import Token


class ClientService:
    """Manages OAuth client registration and lifecycle within a tenant boundary."""

    def __init__(self, db: AsyncSession) -> None:
        self._repo = ClientRepository(db)
        self._db = db

    async def register_client(
        self,
        tenant_id: UUID,
        name: str,
        redirect_uris: list[str],
        grant_types: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> dict[str, str]:
        """Register a new OAuth client.

        Generates a unique ``client_id`` and ``client_secret``. The secret
        is hashed with Argon2id before persisting; the raw secret is
        returned only once.

        Returns a dict with ``client_id``, ``client_secret``, ``name``.
        """
        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(48)

        client = Client(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret_hash=hash_password(client_secret),
            name=name,
            redirect_uris=" ".join(redirect_uris),
            grant_types=" ".join(grant_types or ["authorization_code"]),
            scopes=" ".join(scopes or ["openid"]),
            is_active=True,
        )
        created = await self._repo.create(client)

        return {
            "client_id": created.client_id,
            "client_secret": client_secret,
            "name": created.name,
        }

    async def validate_client(
        self,
        client_id: str,
        client_secret: str | None,
        tenant_id: UUID,
        grant_type: str | None = None,
    ) -> Client:
        """Verify a client exists, is active, and is tenant-bound.

        If ``client_secret`` is provided, it is verified against the stored
        hash. If ``grant_type`` is provided, it is checked against the
        client's allowed grant types.

        Returns the Client model on success.

        Raises:
            UnauthorizedError: If the client is not found, inactive, or
                the secret is wrong.
        """
        client = await self._repo.get_by_client_id(client_id, tenant_id)
        if client is None:
            raise UnauthorizedError(detail="Unknown client.")

        if not client.is_active:
            raise UnauthorizedError(detail="Client is inactive.")

        if client_secret is not None and not verify_password(client.client_secret_hash, client_secret):
            raise UnauthorizedError(detail="Invalid client credentials.")

        if grant_type is not None:
            allowed = client.grant_types.split()
            if grant_type not in allowed:
                raise UnauthorizedError(detail=f"Grant type '{grant_type}' not allowed for this client.")

        return client

    async def revoke_client(self, client_id: str, tenant_id: UUID) -> None:
        """Deactivate a client and revoke all its tokens.

        Raises:
            NotFoundError: If the client is not found in this tenant.
        """
        client = await self._repo.get_by_client_id(client_id, tenant_id)
        if client is None:
            raise NotFoundError(detail="Client not found.")

        client.is_active = False

        # Revoke all access tokens
        stmt = (
            update(Token)
            .where(Token.client_id == client_id, Token.tenant_id == tenant_id, Token.revoked.is_(False))
            .values(revoked=True)
        )
        await self._db.execute(stmt)

        # Revoke all refresh tokens
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

    async def list_clients(self, tenant_id: UUID) -> list[Client]:
        """List all OAuth clients within the current tenant."""
        return await self._repo.list_by_tenant(tenant_id)
