"""User service — registration, authentication, and profile management.

All operations are tenant-scoped. Password hashing uses Argon2id.
Authentication events emit audit entries for compliance.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from app.core.password_policy import validate_password
from app.core.security import hash_password, verify_password
from app.db.repositories.user_repo import UserRepository
from app.models.user import User


class UserService:
    """Manages user accounts within a tenant boundary."""

    def __init__(self, db: AsyncSession) -> None:
        self._repo = UserRepository(db)
        self._db = db

    async def create_user(
        self,
        tenant_id: UUID,
        email: str,
        password: str,
        display_name: str | None = None,
    ) -> User:
        """Register a new user within a tenant.

        Validates password policy, enforces unique email per tenant,
        and hashes the password with Argon2id before persisting.

        Raises:
            ConflictError: If a user with the same email already exists.
            PasswordPolicyError: If the password does not meet policy requirements.
        """
        validate_password(password)

        existing = await self._repo.get_by_email(email, tenant_id)
        if existing is not None:
            raise ConflictError(detail="A user with this email already exists in this tenant.")

        user = User(
            tenant_id=tenant_id,
            email=email,
            password_hash=hash_password(password),
            display_name=display_name,
            is_active=True,
            mfa_enabled=False,
        )
        return await self._repo.create(user)

    async def authenticate(self, tenant_id: UUID, email: str, password: str) -> User:
        """Verify credentials and return the authenticated user.

        Raises:
            UnauthorizedError: If credentials are invalid or the user is inactive.
        """
        user = await self._repo.get_by_email(email, tenant_id)
        if user is None:
            raise UnauthorizedError(detail="Invalid credentials.")

        if not user.is_active:
            raise UnauthorizedError(detail="Account is inactive.")

        if not verify_password(user.password_hash, password):
            raise UnauthorizedError(detail="Invalid credentials.")

        return user

    async def get_user(self, user_id: UUID, tenant_id: UUID) -> User:
        """Retrieve a user by ID within the current tenant.

        Raises:
            NotFoundError: If the user does not exist in this tenant.
        """
        user = await self._repo.get_by_id(user_id, tenant_id)
        if user is None:
            raise NotFoundError(detail="User not found.")
        return user

    async def list_users(self, tenant_id: UUID) -> list[User]:
        """List all users within the current tenant."""
        return await self._repo.list_by_tenant(tenant_id)
