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

"""Administration endpoints (requires elevated RBAC + MFA)."""

from typing import Any

from fastapi import APIRouter, Depends

from app.core.audit import AuditAction, AuditEvent
from app.core.tenant_context import TenantContext
from app.deps import (
    get_audit_service,
    get_client_service,
    get_tenant,
    require_permission,
)
from app.schemas.client import ClientCreate
from app.services.audit_service import AuditService
from app.services.client_service import ClientService

router = APIRouter()


@router.get("/audit-events", dependencies=[Depends(require_permission("admin", "read"))])
async def list_audit_events(
    action: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(get_tenant),
    audit_svc: AuditService = Depends(get_audit_service),
) -> list[dict[str, Any]]:
    """Retrieve audit events for the current tenant."""
    return await audit_svc.query(tenant.tenant_id, action=action, limit=limit)


@router.post("/clients", dependencies=[Depends(require_permission("clients", "write"))])
async def register_client(
    body: ClientCreate,
    tenant: TenantContext = Depends(get_tenant),
    client_svc: ClientService = Depends(get_client_service),
    audit_svc: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
    """Register a new OAuth client for the tenant."""
    result = await client_svc.register_client(
        tenant_id=tenant.tenant_id,
        name=body.name,
        redirect_uris=body.redirect_uris,
        grant_types=body.grant_types,
        scopes=body.scopes,
    )

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.ADMIN_ACTION,
            tenant_id=tenant.tenant_id,
            details={"action": "client.registered", "client_name": body.name},
        )
    )

    return result


@router.delete(
    "/clients/{client_id}",
    dependencies=[Depends(require_permission("clients", "delete"))],
)
async def revoke_client(
    client_id: str,
    tenant: TenantContext = Depends(get_tenant),
    client_svc: ClientService = Depends(get_client_service),
    audit_svc: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
    """Revoke an OAuth client and all its tokens."""
    await client_svc.revoke_client(client_id, tenant.tenant_id)

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.ADMIN_ACTION,
            tenant_id=tenant.tenant_id,
            details={"action": "client.revoked", "client_id": client_id},
        )
    )

    return {"status": "revoked"}
