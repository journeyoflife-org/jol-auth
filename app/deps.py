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

"""FastAPI dependency injection helpers for services and DB sessions."""

from collections.abc import AsyncGenerator, Awaitable, Callable
from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.rbac import Permission, RBACEnforcer
from app.core.rbac import Role as RoleDataclass
from app.core.tenant_context import TenantContext
from app.db.session import async_session_factory
from app.models.role import Role as RoleModel
from app.models.user import User
from app.security.jwks_provider import JWKSProvider
from app.security.jwt_signing import JWTSigner
from app.security.key_manager import KeyManager
from app.services.audit_service import AuditService
from app.services.client_service import ClientService
from app.services.discovery_service import DiscoveryService
from app.services.mfa_service import MFAService
from app.services.revocation_service import RevocationService
from app.services.session_service import SessionService
from app.services.tenant_service import TenantService
from app.services.token_service import TokenService
from app.services.user_service import UserService


async def get_db(request: Request = None) -> AsyncGenerator[AsyncSession, None]:
    """Yield a DB session per request with RLS tenant context set.

    If a tenant is resolved on the request state, sets the PostgreSQL
    session variable ``app.tenant_id`` so that Row Level Security policies
    enforce tenant isolation at the database level.
    """
    async with async_session_factory() as session:
        # Set RLS context if tenant is available
        if request is not None:
            tenant = getattr(request.state, "tenant", None)
            if tenant is not None:
                await session.execute(
                    sa_text("SET LOCAL app.tenant_id = :tid"),
                    {"tid": str(tenant.tenant_id)},
                )
        yield session


def get_tenant(request: Request) -> TenantContext:
    """Extract the resolved tenant from request state."""
    return request.state.tenant  # type: ignore[no-any-return]


def get_key_manager(request: Request) -> KeyManager:
    """Return the application-level KeyManager singleton."""
    return request.app.state.key_manager  # type: ignore[no-any-return]


def get_jwt_signer(request: Request) -> JWTSigner:
    """Return the application-level JWTSigner singleton."""
    return request.app.state.jwt_signer  # type: ignore[no-any-return]


def get_jwks_provider(request: Request) -> JWKSProvider:
    """Return the application-level JWKSProvider singleton."""
    return request.app.state.jwks_provider  # type: ignore[no-any-return]


def get_discovery_service() -> DiscoveryService:
    """Return a DiscoveryService instance."""
    return DiscoveryService()


def get_audit_service(db: AsyncSession = Depends(get_db)) -> AuditService:
    return AuditService(db)


def get_token_service(
    db: AsyncSession = Depends(get_db),
    signer: JWTSigner = Depends(get_jwt_signer),
) -> TokenService:
    return TokenService(db, signer)


def get_user_service(db: AsyncSession = Depends(get_db)) -> UserService:
    return UserService(db)


def get_session_service(db: AsyncSession = Depends(get_db)) -> SessionService:
    return SessionService(db)


def get_mfa_service(db: AsyncSession = Depends(get_db)) -> MFAService:
    return MFAService(db)


def get_client_service(db: AsyncSession = Depends(get_db)) -> ClientService:
    return ClientService(db)


def get_tenant_service(db: AsyncSession = Depends(get_db)) -> TenantService:
    return TenantService(db)


def get_revocation_service(db: AsyncSession = Depends(get_db)) -> RevocationService:
    return RevocationService(db)


# ---------------------------------------------------------------------------
# Authentication & Authorization dependencies
# ---------------------------------------------------------------------------


async def get_current_user(
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
    token_svc: TokenService = Depends(get_token_service),
    user_svc: UserService = Depends(get_user_service),
) -> User:
    """Extract and validate the Bearer token, returning the authenticated user.

    Sets ``request.state.user_id`` and ``request.state.current_user`` for
    downstream handlers (e.g. the ``/authorize`` endpoint reads
    ``request.state.user_id``).

    Raises:
        UnauthorizedError: If the token is missing, invalid, expired, or the
            user is inactive.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise UnauthorizedError(detail="Missing Bearer token.")

    token = auth_header.removeprefix("Bearer ")
    claims = await token_svc.validate_access_token(token, tenant.tenant_id)
    if claims is None:
        raise UnauthorizedError(detail="Invalid or expired token.")

    user_id_str = claims.get("sub")
    if not user_id_str:
        raise UnauthorizedError(detail="Token does not identify a user.")

    try:
        user_id = UUID(user_id_str)
    except (ValueError, AttributeError):
        raise UnauthorizedError(detail="Invalid user identifier in token.") from None

    user = await user_svc.get_user(user_id, tenant.tenant_id)
    if user is None:
        raise UnauthorizedError(detail="User not found.")

    if not user.is_active:
        raise UnauthorizedError(detail="Account is inactive.")

    # Store in request state for downstream handlers
    request.state.current_user = user
    request.state.user_id = user.id

    return user


async def get_current_user_id(
    current_user: User = Depends(get_current_user),
) -> UUID:
    """Return the UUID of the authenticated user."""
    return current_user.id


def require_permission(resource: str, action: str) -> Callable[..., Awaitable[User]]:
    """Dependency factory requiring a specific RBAC permission.

    Usage::

        @router.delete(
            "/admin/data",
            dependencies=[Depends(require_permission("admin", "write"))],
        )
        async def delete_admin_data(): ...

    The user's ``roles`` field (comma-separated role names) is parsed and
    each role is looked up in the tenant's ``roles`` table.  Role
    ``permissions`` are stored as comma-separated ``"resource:action"``
    strings and checked via :class:`~app.core.rbac.RBACEnforcer`.
    """

    async def _checker(
        current_user: User = Depends(get_current_user),
        tenant: TenantContext = Depends(get_tenant),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        if not current_user.roles:
            raise ForbiddenError(detail="No roles assigned.")

        role_names = [r.strip() for r in current_user.roles.split(",") if r.strip()]
        if not role_names:
            raise ForbiddenError(detail="No roles assigned.")

        stmt = select(RoleModel).where(
            RoleModel.tenant_id == tenant.tenant_id,
            RoleModel.name.in_(role_names),
        )
        result = await db.execute(stmt)
        role_models = result.scalars().all()

        enforcer = RBACEnforcer(tenant)
        for rm in role_models:
            perms: list[Permission] = []
            for perm_str in rm.permissions.split(","):
                perm_str = perm_str.strip()
                if ":" in perm_str:
                    res, act = perm_str.split(":", 1)
                    perms.append(Permission(resource=res.strip(), action=act.strip()))

            role_dc = RoleDataclass(name=rm.name, permissions=perms)
            if enforcer.has_permission(role_dc, resource, action):
                return current_user

        raise ForbiddenError(detail=f"Missing permission: {action} on {resource}")

    return _checker
