"""User management endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends

from app.core.audit import AuditAction, AuditEvent
from app.core.tenant_context import TenantContext
from app.deps import get_audit_service, get_current_user, get_tenant, get_user_service
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services.audit_service import AuditService
from app.services.user_service import UserService

router = APIRouter()


@router.get("/")
async def list_users(
    tenant: TenantContext = Depends(get_tenant),
    svc: UserService = Depends(get_user_service),
    current_user: User = Depends(get_current_user),
) -> list[UserResponse]:
    """List users within the current tenant."""
    users = await svc.list_users(tenant.tenant_id)
    return [UserResponse.model_validate(u) for u in users]


@router.post("/")
async def create_user(
    body: UserCreate,
    tenant: TenantContext = Depends(get_tenant),
    svc: UserService = Depends(get_user_service),
    audit_svc: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Create a new user within the current tenant."""
    user = await svc.create_user(
        tenant_id=tenant.tenant_id,
        email=body.email,
        password=body.password,
        display_name=body.display_name,
    )

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.USER_CREATED,
            tenant_id=tenant.tenant_id,
            target_id=user.id,
            details={"email": body.email},
        )
    )

    return UserResponse.model_validate(user)


@router.get("/{user_id}")
async def get_user(
    user_id: UUID,
    tenant: TenantContext = Depends(get_tenant),
    svc: UserService = Depends(get_user_service),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Retrieve a user by ID."""
    user = await svc.get_user(user_id, tenant.tenant_id)
    return UserResponse.model_validate(user)


@router.patch("/{user_id}")
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    tenant: TenantContext = Depends(get_tenant),
    svc: UserService = Depends(get_user_service),
    audit_svc: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Update user profile."""
    user = await svc.get_user(user_id, tenant.tenant_id)

    if body.display_name is not None:
        user.display_name = body.display_name
    if body.is_active is not None:
        user.is_active = body.is_active

    await svc._db.merge(user)
    await svc._db.commit()
    await svc._db.refresh(user)

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.USER_UPDATED,
            tenant_id=tenant.tenant_id,
            target_id=user_id,
            details={"changes": body.model_dump(exclude_none=True)},
        )
    )

    return UserResponse.model_validate(user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    tenant: TenantContext = Depends(get_tenant),
    svc: UserService = Depends(get_user_service),
    audit_svc: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Deactivate a user account."""
    user = await svc.get_user(user_id, tenant.tenant_id)
    user.is_active = False

    await svc._db.merge(user)
    await svc._db.commit()

    await audit_svc.emit(
        AuditEvent(
            action=AuditAction.USER_DELETED,
            tenant_id=tenant.tenant_id,
            target_id=user_id,
        )
    )

    return {"status": "deactivated"}
