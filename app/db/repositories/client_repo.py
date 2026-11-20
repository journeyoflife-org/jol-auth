"""Client repository — CRUD operations for the clients table."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import Client


class ClientRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_by_client_id(self, client_id: str, tenant_id: UUID) -> Client | None:
        stmt = select(Client).where(Client.client_id == client_id, Client.tenant_id == tenant_id)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(self, tenant_id: UUID) -> list[Client]:
        stmt = select(Client).where(Client.tenant_id == tenant_id).order_by(Client.created_at)
        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def create(self, client: Client) -> Client:
        self._db.add(client)
        await self._db.commit()
        await self._db.refresh(client)
        return client
