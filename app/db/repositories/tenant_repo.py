"""Tenant repository — CRUD operations for the tenants table."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant


class TenantRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_by_id(self, tenant_id: UUID) -> Tenant | None:
        return await self._db.get(Tenant, tenant_id)

    async def get_by_slug(self, slug: str) -> Tenant | None:
        stmt = select(Tenant).where(Tenant.slug == slug)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Tenant]:
        stmt = select(Tenant).order_by(Tenant.created_at)
        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def create(self, tenant: Tenant) -> Tenant:
        self._db.add(tenant)
        await self._db.commit()
        await self._db.refresh(tenant)
        return tenant
