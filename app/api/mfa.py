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

"""Multi-factor authentication endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends

from app.core.audit import AuditAction, AuditEvent
from app.core.tenant_context import TenantContext
from app.deps import get_audit_service, get_current_user, get_mfa_service, get_tenant
from app.models.user import User
from app.schemas.mfa import MFAFactorResponse, TOTPEnrollResponse, TOTPVerifyRequest
from app.services.audit_service import AuditService
from app.services.mfa_service import MFAService

router = APIRouter()


@router.post("/totp/enroll")
async def enroll_totp(
    tenant: TenantContext = Depends(get_tenant),
    svc: MFAService = Depends(get_mfa_service),
    audit_svc: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_user),
) -> TOTPEnrollResponse:
    """Generate a TOTP secret and provisioning URI for enrolment."""
    result = await svc.enroll_totp(tenant.tenant_id, current_user.id)

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.MFA_ENROLLED,
            tenant_id=tenant.tenant_id,
            actor_id=current_user.id,
            details={"factor_type": "totp"},
        )
    )

    return TOTPEnrollResponse(
        secret=str(result["secret"]),
        provisioning_uri=str(result["provisioning_uri"]),
        issuer=str(result["issuer"]),
        digits=int(result["digits"]),
        period=int(result["period"]),
    )


@router.post("/totp/verify")
async def verify_totp(
    body: TOTPVerifyRequest,
    tenant: TenantContext = Depends(get_tenant),
    svc: MFAService = Depends(get_mfa_service),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Verify a TOTP code to complete MFA enrolment or challenge."""
    await svc.verify_totp(tenant.tenant_id, current_user.id, body.code)
    return {"status": "verified"}


@router.get("/factors")
async def list_factors(
    tenant: TenantContext = Depends(get_tenant),
    svc: MFAService = Depends(get_mfa_service),
    current_user: User = Depends(get_current_user),
) -> list[MFAFactorResponse]:
    """List enrolled MFA factors for the authenticated user."""
    factors = await svc.list_factors(tenant.tenant_id, current_user.id)
    return [MFAFactorResponse.model_validate(f) for f in factors]


@router.delete("/factors/{factor_id}")
async def remove_factor(
    factor_id: UUID,
    tenant: TenantContext = Depends(get_tenant),
    svc: MFAService = Depends(get_mfa_service),
    audit_svc: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Remove an enrolled MFA factor."""
    await svc.remove_factor(factor_id, tenant.tenant_id, current_user.id)

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.MFA_REMOVED,
            tenant_id=tenant.tenant_id,
            actor_id=current_user.id,
            target_id=factor_id,
        )
    )

    return {"status": "removed"}
