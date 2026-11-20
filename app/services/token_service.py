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

"""Token service — issuance, validation, refresh, and revocation of OAuth tokens.

Handles the full lifecycle of access tokens (JWT, short-lived), refresh
tokens (opaque, long-lived, rotated on every use), and OIDC ID tokens
(JWT with standard OIDC claims when ``openid`` scope is present).

Security properties:
- Access tokens carry ``tenant_id`` (``tid`` claim) for tenant binding.
- ID tokens carry ``nonce``, ``auth_time``, ``acr``, ``amr`` per OIDC Core 1.0.
- Refresh tokens are stored as SHA-256 hashes; raw values never persisted.
- Refresh rotation invalidates the prior token on every use.
- Reuse of an already-rotated refresh token revokes the entire token family.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import generate_token, sha256_hex
from app.db.repositories.token_repo import TokenRepository
from app.models.refresh_token import RefreshToken
from app.models.token import Token
from app.security.jwt_signing import JWTSigner
from app.security.oidc_claims import build_id_token_claims


class TokenService:
    """Issues, validates, refreshes, and revokes OAuth tokens."""

    def __init__(self, db: AsyncSession, signer: JWTSigner) -> None:
        self._db = db
        self._signer = signer
        self._repo = TokenRepository(db)

    async def issue_tokens(
        self,
        tenant_id: UUID,
        user_id: UUID | None,
        client_id: str,
        scope: str,
        nonce: str | None = None,
        auth_time: int | None = None,
        amr: list[str] | None = None,
        include_id_token: bool = False,
    ) -> dict[str, Any]:
        """Issue a new access token (JWT) and refresh token pair.

        When ``include_id_token`` is True and the ``openid`` scope is present,
        an OIDC ID token is also issued per OpenID Connect Core 1.0.

        Args:
            tenant_id: Tenant UUID for tenant binding.
            user_id: User UUID (None for client_credentials grant).
            client_id: OAuth client identifier.
            scope: Granted scope string (space-separated).
            nonce: Nonce from the authorization request (for ID token).
            auth_time: Unix timestamp of user authentication (for ID token).
            amr: Authentication methods references (for ID token).
            include_id_token: Whether to issue an ID token (authorization_code flow only).

        Returns a dict with keys: ``access_token``, ``refresh_token``,
        ``token_type``, ``expires_in``, ``scope``, and optionally ``id_token``.
        """
        now = datetime.now(tz=UTC)
        access_expires = now + _access_ttl()

        # Build access token claims
        claims: dict[str, Any] = {
            "tid": str(tenant_id),
            "client_id": client_id,
            "scope": scope,
        }
        if user_id:
            claims["sub"] = str(user_id)

        access_token_jti = str(uuid.uuid4())
        claims["jti"] = access_token_jti
        access_token_jwt = self._signer.sign(claims, access_expires)

        # Persist access token metadata for revocation tracking
        access_token_record = Token(
            jti=access_token_jti,
            tenant_id=tenant_id,
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            token_type="Bearer",  # noqa: S106
            expires_at=access_expires,
            revoked=False,
        )
        self._db.add(access_token_record)

        # Generate and persist refresh token (hashed)
        raw_refresh = generate_token(48)
        refresh_hash = sha256_hex(raw_refresh)
        refresh_expires = now + _refresh_ttl()
        family_id = uuid.uuid4()

        refresh_record = RefreshToken(
            token_hash=refresh_hash,
            tenant_id=tenant_id,
            user_id=user_id or uuid.uuid4(),  # client_credentials has no user
            client_id=client_id,
            scope=scope,
            expires_at=refresh_expires,
            revoked=False,
            family_id=family_id,
        )
        self._db.add(refresh_record)
        await self._db.commit()

        result: dict[str, Any] = {
            "access_token": access_token_jwt,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
            "expires_in": int(_access_ttl().total_seconds()),
            "scope": scope,
        }

        # Issue OIDC ID token when openid scope is present and user is authenticated
        scopes_list = scope.split()
        if include_id_token and "openid" in scopes_list and user_id:
            id_token = self._issue_id_token(
                user_id=user_id,
                tenant_id=tenant_id,
                client_id=client_id,
                nonce=nonce,
                auth_time=auth_time,
                amr=amr,
                access_token=access_token_jwt,
            )
            result["id_token"] = id_token

        return result

    def _issue_id_token(
        self,
        user_id: UUID,
        tenant_id: UUID,
        client_id: str,
        nonce: str | None = None,
        auth_time: int | None = None,
        amr: list[str] | None = None,
        access_token: str | None = None,
    ) -> str:
        """Sign and return an OIDC ID token.

        The ID token audience is the client_id (per OIDC Core §2).
        The ``acr`` claim defaults to ``"urn:openid:acr:basic"`` if not
        overridden by a future authentication policy.
        """
        user_record = {
            "id": user_id,
            "email": None,  # Could be enriched by loading user from DB
            "display_name": None,
        }

        claims = build_id_token_claims(
            user=user_record,
            issuer=settings.jwt_issuer,
            audience=client_id,  # ID token audience is the client_id per OIDC Core
            nonce=nonce,
            auth_time=auth_time,
            acr="urn:openid:acr:basic",
            amr=amr or ["pwd"],
            access_token=access_token,
        )

        # ID tokens expire after 15 minutes (short-lived)
        from datetime import timedelta

        id_token_expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        return self._signer.sign(claims, id_token_expires)

    async def validate_access_token(self, token: str, tenant_id: UUID) -> dict[str, Any] | None:
        """Verify a JWT access token and return its claims, or ``None`` if invalid.

        Checks:
        - Signature and standard claims (iss, aud, exp)
        - ``tid`` claim matches the requesting tenant
        - Token has not been revoked
        """
        try:
            payload = self._signer.verify(token)
        except Exception:
            return None

        # Tenant binding check
        token_tenant = payload.get("tid")
        if token_tenant != str(tenant_id):
            return None

        # Revocation check
        jti = payload.get("jti")
        if jti:
            record = await self._repo.get_by_jti(jti)
            if record and record.revoked:
                return None

        return payload

    async def refresh_tokens(self, raw_refresh_token: str, tenant_id: UUID) -> dict[str, Any]:
        """Rotate a refresh token: revoke the old one, issue a new pair.

        If the presented refresh token was already revoked (reuse detected),
        the entire token family is revoked as a theft-detection measure.

        Raises:
            ValueError: If the refresh token is invalid, expired, or belongs
                to a different tenant.
        """
        refresh_hash = sha256_hex(raw_refresh_token)

        # Look up the refresh token — must use raw SQL since we store hashes
        from sqlalchemy import select

        stmt = select(RefreshToken).where(RefreshToken.token_hash == refresh_hash)
        result = await self._db.execute(stmt)
        record = result.scalar_one_or_none()

        if record is None:
            raise ValueError("Invalid refresh token.")

        if record.tenant_id != tenant_id:
            raise ValueError("Cross-tenant refresh attempt.")

        # Reuse detection: if already revoked, revoke the entire family
        if record.revoked:
            await self._revoke_family(record.family_id)
            raise ValueError("Refresh token reuse detected — family revoked.")

        if record.expires_at < datetime.now(tz=UTC):
            record.revoked = True
            await self._db.commit()
            raise ValueError("Refresh token expired.")

        # Revoke the current refresh token (rotation)
        record.revoked = True
        await self._db.commit()

        # Issue new pair with same scope/client/user
        return await self.issue_tokens(
            tenant_id=tenant_id,
            user_id=record.user_id if record.user_id != uuid.UUID(int=0) else None,
            client_id=record.client_id,
            scope=record.scope,
        )

    async def revoke_token(self, token: str, tenant_id: UUID) -> None:
        """Revoke a specific token by its JTI (access) or raw value (refresh).

        This method is intentionally tolerant — revoking an already-revoked
        or unknown token succeeds silently (RFC 7009 compliance).
        """
        # Try as access token (decode JWT to find jti)
        try:
            payload = self._signer.verify(token)
            jti = payload.get("jti")
            if jti:
                await self._repo.revoke_by_jti(jti)
                return
        except Exception:  # noqa: S110  -- RFC 7009: silently fall through to refresh-token lookup
            pass

        # Try as refresh token (hash and lookup)
        refresh_hash = sha256_hex(token)
        from sqlalchemy import select

        stmt = select(RefreshToken).where(RefreshToken.token_hash == refresh_hash, RefreshToken.tenant_id == tenant_id)
        result = await self._db.execute(stmt)
        record = result.scalar_one_or_none()
        if record:
            record.revoked = True
            await self._db.commit()

    async def _revoke_family(self, family_id: UUID) -> None:
        """Revoke all refresh tokens in a family (theft response)."""
        from sqlalchemy import update

        stmt = update(RefreshToken).where(RefreshToken.family_id == family_id).values(revoked=True)
        await self._db.execute(stmt)
        await self._db.commit()


def _access_ttl() -> timedelta:
    """Return access token TTL as a timedelta."""
    return timedelta(seconds=settings.oauth_access_token_ttl)


def _refresh_ttl() -> timedelta:
    """Return refresh token TTL as a timedelta."""
    return timedelta(seconds=settings.oauth_refresh_token_ttl)
