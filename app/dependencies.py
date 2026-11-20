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
