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

"""Token repository — CRUD operations for tokens and refresh tokens."""

from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.refresh_token import RefreshToken
from app.models.token import Token


class TokenRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_by_jti(self, jti: str) -> Token | None:
        stmt = select(Token).where(Token.jti == jti)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def revoke_by_jti(self, jti: str) -> None:
        stmt = update(Token).where(Token.jti == jti).values(revoked=True)
        await self._db.execute(stmt)
        await self._db.commit()

    async def revoke_all_for_user(self, user_id: UUID, tenant_id: UUID) -> None:
        stmt = update(Token).where(Token.user_id == user_id, Token.tenant_id == tenant_id).values(revoked=True)
        await self._db.execute(stmt)
        await self._db.commit()

    async def create_refresh(self, refresh_token: RefreshToken) -> RefreshToken:
        self._db.add(refresh_token)
        await self._db.commit()
        await self._db.refresh(refresh_token)
        return refresh_token
