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

"""Tenant service — creation, lookup, and configuration management.

All tenant operations enforce uniqueness of slug.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, NotFoundError
from app.db.repositories.tenant_repo import TenantRepository
from app.models.tenant import Tenant


class TenantService:
    """Manages tenant lifecycle and configuration."""

    def __init__(self, db: AsyncSession) -> None:
        self._repo = TenantRepository(db)
        self._db = db

    async def create_tenant(self, name: str, slug: str, region: str) -> Tenant:
        """Register a new tenant.

        Raises:
            ConflictError: If a tenant with the same slug already exists.
        """
        existing = await self._repo.get_by_slug(slug)
        if existing is not None:
            raise ConflictError(detail="A tenant with this slug already exists.")

        tenant = Tenant(name=name, slug=slug, region=region, is_active=True)
        return await self._repo.create(tenant)

    async def get_tenant(self, tenant_id: UUID) -> Tenant:
        """Retrieve a tenant by ID.

        Raises:
            NotFoundError: If the tenant does not exist.
        """
        tenant = await self._repo.get_by_id(tenant_id)
        if tenant is None:
            raise NotFoundError(detail="Tenant not found.")
        return tenant

    async def list_tenants(self) -> list[Tenant]:
        """List all tenants."""
        return await self._repo.list_all()

    async def update_tenant(self, tenant_id: UUID, **kwargs: object) -> Tenant:
        """Update tenant configuration.

        Accepted keyword arguments: ``name``, ``is_active``.

        Raises:
            NotFoundError: If the tenant does not exist.
        """
        tenant = await self._repo.get_by_id(tenant_id)
        if tenant is None:
            raise NotFoundError(detail="Tenant not found.")

        if "name" in kwargs and kwargs["name"] is not None:
            tenant.name = str(kwargs["name"])
        if "is_active" in kwargs and kwargs["is_active"] is not None:
            tenant.is_active = bool(kwargs["is_active"])

        await self._db.merge(tenant)
        await self._db.commit()
        await self._db.refresh(tenant)
        return tenant
