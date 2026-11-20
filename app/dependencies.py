"""FastAPI dependency injection providers."""

from collections.abc import AsyncGenerator

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import RBACEnforcer
from app.core.tenant_context import TenantContext
from app.db.session import async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session scoped to the current request."""
    async with async_session_factory() as session:
        yield session


async def get_tenant_context(request: Request) -> TenantContext:
    """Return the resolved tenant context for the current request."""
    tenant: TenantContext | None = getattr(request.state, "tenant", None)
    if tenant is None:
        raise RuntimeError("Tenant context not resolved — TenantResolutionMiddleware may be missing.")
    return tenant


async def get_rbac_enforcer(
    tenant: TenantContext = Depends(get_tenant_context),
) -> RBACEnforcer:
    """Return an RBAC enforcer bound to the current tenant."""
    return RBACEnforcer(tenant=tenant)
