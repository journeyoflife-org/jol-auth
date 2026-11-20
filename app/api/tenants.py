"""Tenant management endpoints (admin)."""

from uuid import UUID

from fastapi import APIRouter, Depends

from app.deps import get_tenant_service, require_permission
from app.schemas.tenant import TenantCreate, TenantResponse, TenantUpdate
from app.services.tenant_service import TenantService

router = APIRouter()


@router.get("/", dependencies=[Depends(require_permission("tenants", "read"))])
async def list_tenants(
    svc: TenantService = Depends(get_tenant_service),
) -> list[TenantResponse]:
    """List all tenants (admin only)."""
    tenants = await svc.list_tenants()
    return [TenantResponse.model_validate(t) for t in tenants]


@router.post("/", dependencies=[Depends(require_permission("tenants", "write"))])
async def create_tenant(
    body: TenantCreate,
    svc: TenantService = Depends(get_tenant_service),
) -> TenantResponse:
    """Register a new tenant."""
    tenant = await svc.create_tenant(
        name=body.name,
        slug=body.slug,
        region=body.region,
    )
    return TenantResponse.model_validate(tenant)


@router.get("/{tenant_id}", dependencies=[Depends(require_permission("tenants", "read"))])
async def get_tenant_by_id(
    tenant_id: UUID,
    svc: TenantService = Depends(get_tenant_service),
) -> TenantResponse:
    """Retrieve tenant details."""
    tenant = await svc.get_tenant(tenant_id)
    return TenantResponse.model_validate(tenant)


@router.patch("/{tenant_id}", dependencies=[Depends(require_permission("tenants", "write"))])
async def update_tenant(
    tenant_id: UUID,
    body: TenantUpdate,
    svc: TenantService = Depends(get_tenant_service),
) -> TenantResponse:
    """Update tenant configuration."""
    tenant = await svc.update_tenant(
        tenant_id,
        name=body.name,
        is_active=body.is_active,
    )
    return TenantResponse.model_validate(tenant)
