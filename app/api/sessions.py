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

"""Session management endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends

from app.core.audit import AuditAction, AuditEvent
from app.core.tenant_context import TenantContext
from app.deps import get_audit_service, get_current_user, get_session_service, get_tenant
from app.models.user import User
from app.schemas.session import SessionResponse
from app.services.audit_service import AuditService
from app.services.session_service import SessionService

router = APIRouter()


@router.get("/")
async def list_sessions(
    tenant: TenantContext = Depends(get_tenant),
    session_svc: SessionService = Depends(get_session_service),
    current_user: User = Depends(get_current_user),
) -> list[SessionResponse]:
    """List active sessions for the authenticated user within the current tenant."""
    sessions = await session_svc.get_active_sessions(tenant.tenant_id, current_user.id)
    return [SessionResponse.model_validate(s) for s in sessions]


@router.delete("/{session_id}")
async def revoke_session(
    session_id: UUID,
    tenant: TenantContext = Depends(get_tenant),
    session_svc: SessionService = Depends(get_session_service),
    audit_svc: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Revoke a specific session. Tenant-scoped."""
    await session_svc.revoke_session(session_id, tenant.tenant_id)

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.SESSION_REVOKED,
            tenant_id=tenant.tenant_id,
            actor_id=current_user.id,
            target_id=session_id,
        )
    )

    return {"status": "revoked"}
