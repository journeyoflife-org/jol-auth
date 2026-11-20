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

"""OAuth 2.0 endpoints — token, authorize, revoke, introspect.

Implements the core OAuth 2.0 flows:
- Authorization Code (with PKCE)
- Client Credentials
- Refresh Token
- Token Revocation (RFC 7009)
- Token Introspection (RFC 7662)
"""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select

from app.core.audit import AuditAction, AuditEvent
from app.core.exceptions import AuthError, UnauthorizedError
from app.core.security import generate_token, sha256_hex
from app.core.tenant_context import TenantContext
from app.db.session import async_session_factory
from app.deps import (
    get_audit_service,
    get_client_service,
    get_tenant,
    get_token_service,
)
from app.models.authorization_code import AuthorizationCode
from app.schemas.token import TokenResponse
from app.security.oauth_validators import validate_scope
from app.security.pkce import verify_code_challenge
from app.services.audit_service import AuditService
from app.services.client_service import ClientService
from app.services.token_service import TokenService

router = APIRouter()


@router.post("/authorize")
async def authorize(
    request: Request,
    response_type: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("openid"),
    state: str = Form(""),
    nonce: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
    tenant: TenantContext = Depends(get_tenant),
    client_svc: ClientService = Depends(get_client_service),
) -> dict[str, str]:
    """Initiate an authorization code grant.

    Returns an authorization code that can be exchanged for tokens.
    Requires the user to be authenticated (sub from request state).
    The ``nonce`` parameter is stored with the code and included in the
    ID token per OIDC Core 1.0 §3.1.2.1.
    """
    if response_type != "code":
        raise AuthError(status_code=400, detail="Only response_type=code is supported.")

    # Validate client
    await client_svc.validate_client(client_id, None, tenant.tenant_id, "authorization_code")

    # Generate authorization code
    raw_code = generate_token(32)
    code_hash = sha256_hex(raw_code)

    from app.core.token_policy import TokenPolicy

    policy = TokenPolicy()
    expires_at = policy.authorization_code_expiry()

    # Get user_id from request state (set by auth middleware or session)
    user_id = getattr(request.state, "user_id", None)
    if user_id is None:
        raise UnauthorizedError(detail="User must be authenticated.")

    auth_code = AuthorizationCode(
        code_hash=code_hash,
        tenant_id=tenant.tenant_id,
        user_id=user_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce or None,
        code_challenge=code_challenge or None,
        code_challenge_method=code_challenge_method if code_challenge else None,
        expires_at=expires_at,
    )

    async with async_session_factory() as db:
        db.add(auth_code)
        await db.commit()

    return {
        "code": raw_code,
        "state": state,
        "redirect_uri": redirect_uri,
    }


@router.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    refresh_token: str | None = Form(None),
    scope: str = Form("openid"),
    code_verifier: str | None = Form(None),
    tenant: TenantContext = Depends(get_tenant),
    token_svc: TokenService = Depends(get_token_service),
    client_svc: ClientService = Depends(get_client_service),
    audit_svc: AuditService = Depends(get_audit_service),
) -> TokenResponse:
    """Exchange an authorization code or client credentials for tokens."""
    if grant_type == "authorization_code":
        return await _handle_authorization_code(
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
            tenant=tenant,
            token_svc=token_svc,
            client_svc=client_svc,
            audit_svc=audit_svc,
        )

    if grant_type == "client_credentials":
        return await _handle_client_credentials(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            tenant=tenant,
            token_svc=token_svc,
            client_svc=client_svc,
            audit_svc=audit_svc,
        )

    if grant_type == "refresh_token":
        return await _handle_refresh_token(
            refresh_token=refresh_token,
            tenant=tenant,
            token_svc=token_svc,
            audit_svc=audit_svc,
        )

    raise AuthError(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


async def _handle_authorization_code(
    *,
    code: str | None,
    redirect_uri: str | None,
    client_id: str,
    client_secret: str | None,
    code_verifier: str | None,
    tenant: TenantContext,
    token_svc: TokenService,
    client_svc: ClientService,
    audit_svc: AuditService,
) -> TokenResponse:
    """Process authorization code exchange."""
    if not code:
        raise AuthError(status_code=400, detail="Missing 'code' parameter.")

    # Validate client
    await client_svc.validate_client(client_id, client_secret, tenant.tenant_id, "authorization_code")

    # Look up the authorization code
    code_hash = sha256_hex(code)
    async with async_session_factory() as db:
        stmt = select(AuthorizationCode).where(
            AuthorizationCode.code_hash == code_hash,
            AuthorizationCode.tenant_id == tenant.tenant_id,
        )
        result = await db.execute(stmt)
        auth_code = result.scalar_one_or_none()

        if auth_code is None:
            raise AuthError(status_code=400, detail="Invalid authorization code.")

        if auth_code.consumed:
            raise AuthError(status_code=400, detail="Authorization code already consumed.")

        if auth_code.expires_at < datetime.now(tz=UTC):
            raise AuthError(status_code=400, detail="Authorization code expired.")

        if auth_code.client_id != client_id:
            raise AuthError(status_code=400, detail="Client mismatch.")

        if redirect_uri and auth_code.redirect_uri != redirect_uri:
            raise AuthError(status_code=400, detail="redirect_uri mismatch.")

        # PKCE verification
        if auth_code.code_challenge:
            if not code_verifier:
                raise AuthError(status_code=400, detail="Missing code_verifier.")
            method = auth_code.code_challenge_method or "S256"
            if not verify_code_challenge(code_verifier, auth_code.code_challenge, method):
                raise AuthError(status_code=400, detail="PKCE verification failed.")

        # Mark as consumed
        auth_code.consumed = True
        await db.commit()

    # Issue tokens — include ID token for OIDC compliance
    token_data = await token_svc.issue_tokens(
        tenant_id=tenant.tenant_id,
        user_id=auth_code.user_id,
        client_id=client_id,
        scope=auth_code.scope,
        nonce=auth_code.nonce,
        auth_time=int(datetime.now(tz=UTC).timestamp()),
        amr=["pwd"],
        include_id_token=True,
    )

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.TOKEN_ISSUED,
            tenant_id=tenant.tenant_id,
            actor_id=auth_code.user_id,
            details={"grant_type": "authorization_code", "client_id": client_id},
        )
    )

    return TokenResponse(**token_data)


async def _handle_client_credentials(
    *,
    client_id: str,
    client_secret: str | None,
    scope: str,
    tenant: TenantContext,
    token_svc: TokenService,
    client_svc: ClientService,
    audit_svc: AuditService,
) -> TokenResponse:
    """Process client credentials grant."""
    if not client_secret:
        raise AuthError(status_code=400, detail="Missing 'client_secret'.")

    client = await client_svc.validate_client(client_id, client_secret, tenant.tenant_id, "client_credentials")

    # Intersect requested scope with client scope
    valid_scopes = validate_scope(scope, client.scopes)
    effective_scope = " ".join(valid_scopes)

    result = await token_svc.issue_tokens(
        tenant_id=tenant.tenant_id,
        user_id=None,
        client_id=client_id,
        scope=effective_scope,
    )

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.TOKEN_ISSUED,
            tenant_id=tenant.tenant_id,
            details={"grant_type": "client_credentials", "client_id": client_id},
        )
    )

    return TokenResponse(**result)


async def _handle_refresh_token(
    *,
    refresh_token: str | None,
    tenant: TenantContext,
    token_svc: TokenService,
    audit_svc: AuditService,
) -> TokenResponse:
    """Process refresh token rotation."""
    if not refresh_token:
        raise AuthError(status_code=400, detail="Missing 'refresh_token' parameter.")

    try:
        result = await token_svc.refresh_tokens(refresh_token, tenant.tenant_id)
    except ValueError as exc:
        raise AuthError(status_code=400, detail=str(exc)) from None

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.TOKEN_REFRESHED,
            tenant_id=tenant.tenant_id,
            details={"grant_type": "refresh_token"},
        )
    )

    return TokenResponse(**result)


@router.post("/revoke")
async def revoke(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    tenant: TenantContext = Depends(get_tenant),
    token_svc: TokenService = Depends(get_token_service),
    audit_svc: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
    """Revoke a token (RFC 7009).

    Always returns 200 regardless of whether the token was found.
    """
    await token_svc.revoke_token(token, tenant.tenant_id)

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.TOKEN_REVOKED,
            tenant_id=tenant.tenant_id,
            details={"token_type_hint": token_type_hint},
        )
    )

    return {}  # RFC 7009 — always 200


@router.post("/introspect")
async def introspect(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    tenant: TenantContext = Depends(get_tenant),
    token_svc: TokenService = Depends(get_token_service),
) -> dict[str, Any]:
    """Introspect a token (RFC 7662).

    Returns ``active: true`` with claims if the token is valid,
    ``active: false`` otherwise.
    """
    claims = await token_svc.validate_access_token(token, tenant.tenant_id)

    if claims is None:
        return {"active": False}

    return {
        "active": True,
        "scope": claims.get("scope"),
        "client_id": claims.get("client_id"),
        "sub": claims.get("sub"),
        "iss": claims.get("iss"),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "token_type": "Bearer",
    }
