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
