"""User repository — CRUD operations for the users table."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


class UserRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_by_id(self, user_id: UUID, tenant_id: UUID) -> User | None:
        stmt = select(User).where(User.id == user_id, User.tenant_id == tenant_id)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str, tenant_id: UUID) -> User | None:
        stmt = select(User).where(User.email == email, User.tenant_id == tenant_id)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(self, tenant_id: UUID) -> list[User]:
        stmt = select(User).where(User.tenant_id == tenant_id).order_by(User.created_at)
        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def create(self, user: User) -> User:
        self._db.add(user)
        await self._db.commit()
        await self._db.refresh(user)
        return user
