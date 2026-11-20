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

"""Tenant resolution middleware — extracts tenant from X-Tenant-ID header.

Resolution strategy:
1. Read ``X-Tenant-ID`` header
2. Parse as UUID (reject malformed values with 400)
3. Look up the tenant in PostgreSQL via :class:`TenantRepository`
4. Verify the tenant is active (reject inactive with 403)
5. Attach an immutable :class:`TenantContext` to ``request.state.tenant``

Paths in ``EXEMPT_PATHS`` bypass resolution (health, discovery, JWKS).
"""

from uuid import UUID

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.tenant_context import TenantContext
from app.db.repositories.tenant_repo import TenantRepository
from app.db.session import async_session_factory


class TenantResolutionMiddleware(BaseHTTPMiddleware):
    """Resolve the current tenant and attach it to the request state."""

    EXEMPT_PATHS = frozenset(
        {
            "/api/health",
            "/api/oidc/.well-known/openid-configuration",
            "/api/jwks/",
        }
    )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        tenant_id_header = request.headers.get("X-Tenant-ID")
        if not tenant_id_header:
            return JSONResponse(
                status_code=400,
                content={"detail": "Missing X-Tenant-ID header."},
            )

        # Validate UUID format
        try:
            tenant_id = UUID(tenant_id_header)
        except (ValueError, AttributeError):
            return JSONResponse(
                status_code=400,
                content={"detail": "X-Tenant-ID must be a valid UUID."},
            )

        # Resolve tenant from database
        async with async_session_factory() as db:
            repo = TenantRepository(db)
            tenant_model = await repo.get_by_id(tenant_id)

        if tenant_model is None:
            return JSONResponse(
                status_code=403,
                content={"detail": "Unknown tenant."},
            )

        if not tenant_model.is_active:
            return JSONResponse(
                status_code=403,
                content={"detail": "Tenant is inactive."},
            )

        request.state.tenant = TenantContext(
            tenant_id=tenant_model.id,
            name=tenant_model.name,
            region=tenant_model.region,
            is_active=tenant_model.is_active,
        )
        return await call_next(request)
