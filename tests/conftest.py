"""Shared test fixtures — test client, database, and auth helpers.

This conftest provides:
- An in-memory SQLite async database (via aiosqlite), recreated per test
- A patched ``async_session_factory`` so every module uses the test DB
- An httpx ``AsyncClient`` with ASGI transport against the real FastAPI app
- Pre-seeded test tenant, user, role, and OAuth client
- Auth header fixtures: valid / expired / tampered / no-auth / cross-tenant

Every test function gets a fresh database, ensuring full isolation.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from app.config import settings
from app.core.security import hash_password
from app.db import session as db_session_module
from app.db.base import Base
from app.main import create_app

# Import all models so Base.metadata knows about every table. The underscore
# aliases bind nothing the fixtures below reuse (`client`, `tenant`, `user`,
# `role`, `token`), keeping the side-effect registration while avoiding the
# F811 redefinition-of-unused collisions.
from app.models import (
    audit_event as _model_audit_event,  # noqa: F401
)
from app.models import (
    authorization_code as _model_authorization_code,  # noqa: F401
)
from app.models import (
    client as _model_client,  # noqa: F401
)
from app.models import (
    mfa_factor as _model_mfa_factor,  # noqa: F401
)
from app.models import (
    refresh_token as _model_refresh_token,  # noqa: F401
)
from app.models import (
    role as _model_role,  # noqa: F401
)
from app.models import (
    session as _model_session,  # noqa: F401
)
from app.models import (
    tenant as _model_tenant,  # noqa: F401
)
from app.models import (
    token as _model_token,  # noqa: F401
)
from app.models import (
    user as _model_user,  # noqa: F401
)
from app.models.role import Role
from app.models.tenant import Tenant
from app.models.token import Token
from app.models.user import User
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# SQLite compatibility — compile postgresql.UUID as CHAR(32) for SQLite
# ---------------------------------------------------------------------------
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles


@compiles(PG_UUID, "sqlite")
def _compile_pg_uuid_sqlite(type_: object, compiler: object, **kw: object) -> str:
    return "CHAR(32)"


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def test_engine():
    """Create a fresh in-memory SQLite database for each test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def test_session_factory(test_engine) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the test engine."""
    return async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture(autouse=True)
async def patch_db(monkeypatch, test_session_factory):
    """Patch async_session_factory in every module that imported it directly.

    This is autouse so that even tests that only touch the middleware
    (which uses ``async_session_factory`` outside FastAPI's DI) get the
    test database.
    """
    monkeypatch.setattr(db_session_module, "async_session_factory", test_session_factory)

    # Patch modules that did ``from app.db.session import async_session_factory``
    import app.api.oauth as oauth_mod
    import app.middleware.tenant_resolution as tenant_res

    monkeypatch.setattr(oauth_mod, "async_session_factory", test_session_factory)
    monkeypatch.setattr(tenant_res, "async_session_factory", test_session_factory)

    yield


# ---------------------------------------------------------------------------
# App and HTTP client fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app(test_session_factory):
    """Create a FastAPI app with test key management (no lifespan needed)."""
    from app.security.jwks_provider import JWKSProvider
    from app.security.jwt_signing import JWTSigner
    from app.security.key_manager import KeyManager

    app = create_app()

    # Manually initialise security singletons (normally done by lifespan)
    km = KeyManager()
    km.generate_key_pair()
    app.state.key_manager = km
    app.state.jwt_signer = JWTSigner(km, settings.jwt_issuer, settings.jwt_audience)
    app.state.jwks_provider = JWKSProvider(km)

    # Override get_db so all service-layer code uses the test session factory
    from app.deps import get_db

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    yield app
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client against the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Test data fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def test_tenant(test_session_factory) -> Tenant:
    """Create a test tenant in the database."""
    tenant = Tenant(
        id=uuid4(),
        name="Test Institution",
        slug="test-inst",
        region="EU",
        is_active=True,
    )
    async with test_session_factory() as db:
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)
    return tenant


@pytest_asyncio.fixture
async def second_tenant(test_session_factory) -> Tenant:
    """Create a second tenant for cross-tenant isolation tests."""
    tenant = Tenant(
        id=uuid4(),
        name="Other Institution",
        slug="other-inst",
        region="EU",
        is_active=True,
    )
    async with test_session_factory() as db:
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)
    return tenant


@pytest_asyncio.fixture
async def test_user(test_session_factory, test_tenant) -> User:
    """Create a test user with a known password."""
    user = User(
        id=uuid4(),
        tenant_id=test_tenant.id,
        email="test@example.org",
        password_hash=hash_password("TestPassword123!"),
        display_name="Test User",
        is_active=True,
        mfa_enabled=False,
        roles="",
    )
    async with test_session_factory() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_user(test_session_factory, test_tenant) -> User:
    """Create an admin user with the 'admin' role."""
    user = User(
        id=uuid4(),
        tenant_id=test_tenant.id,
        email="admin@example.org",
        password_hash=hash_password("AdminPassword123!"),
        display_name="Admin User",
        is_active=True,
        mfa_enabled=False,
        roles="admin",
    )
    async with test_session_factory() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_role(test_session_factory, test_tenant) -> Role:
    """Create an admin role with full permissions."""
    role = Role(
        id=uuid4(),
        tenant_id=test_tenant.id,
        name="admin",
        permissions=(
            "admin:read,admin:write,users:read,users:write,users:delete,clients:read,clients:write,clients:delete"
        ),
    )
    async with test_session_factory() as db:
        db.add(role)
        await db.commit()
        await db.refresh(role)
    return role


@pytest_asyncio.fixture
async def inactive_user(test_session_factory, test_tenant) -> User:
    """Create a deactivated user (is_active=False)."""
    user = User(
        id=uuid4(),
        tenant_id=test_tenant.id,
        email="inactive@example.org",
        password_hash=hash_password("InactivePassword123!"),
        display_name="Inactive User",
        is_active=False,
        mfa_enabled=False,
        roles="",
    )
    async with test_session_factory() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


async def _persist_token_record(
    test_session_factory,
    tenant_id,
    user_id,
    jti: str,
    expires_at: datetime,
) -> None:
    """Persist a token record for revocation tracking."""
    async with test_session_factory() as db:
        record = Token(
            jti=jti,
            tenant_id=tenant_id,
            user_id=user_id,
            client_id="test-client",
            scope="openid",
            token_type="Bearer",  # noqa: S106 -- RFC 6750 token-type constant, not a credential
            expires_at=expires_at,
            revoked=False,
        )
        db.add(record)
        await db.commit()


def _sign_token(app, user_id, tenant_id, expires_at: datetime) -> str:
    """Sign a JWT with the given claims and expiry."""
    signer = app.state.jwt_signer
    claims = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "client_id": "test-client",
        "scope": "openid",
    }
    return signer.sign(claims, expires_at)


# ---------------------------------------------------------------------------
# Token / header fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_token(app, test_session_factory, test_tenant, test_user) -> str:
    """Generate a valid JWT access token for the test user."""
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=15)
    token = _sign_token(app, test_user.id, test_tenant.id, expires_at)

    payload = app.state.jwt_signer.verify(token)
    await _persist_token_record(test_session_factory, test_tenant.id, test_user.id, payload["jti"], expires_at)
    return token


@pytest_asyncio.fixture
async def admin_token(app, test_session_factory, test_tenant, admin_user, admin_role) -> str:
    """Generate a valid JWT access token for the admin user."""
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=15)
    token = _sign_token(app, admin_user.id, test_tenant.id, expires_at)

    payload = app.state.jwt_signer.verify(token)
    await _persist_token_record(test_session_factory, test_tenant.id, admin_user.id, payload["jti"], expires_at)
    return token


@pytest_asyncio.fixture
async def inactive_token(app, test_session_factory, test_tenant, inactive_user) -> str:
    """Generate a valid JWT for a deactivated user (token itself is not expired)."""
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=15)
    token = _sign_token(app, inactive_user.id, test_tenant.id, expires_at)

    payload = app.state.jwt_signer.verify(token)
    await _persist_token_record(test_session_factory, test_tenant.id, inactive_user.id, payload["jti"], expires_at)
    return token


@pytest_asyncio.fixture
def expired_token(app, test_tenant, test_user) -> str:
    """Generate an expired JWT (exp in the past)."""
    expires_at = datetime.now(tz=UTC) - timedelta(minutes=5)
    return _sign_token(app, test_user.id, test_tenant.id, expires_at)


@pytest_asyncio.fixture
def tampered_token(auth_token) -> str:
    """Tamper with the payload so the signature no longer matches."""
    parts = auth_token.split(".")
    # Flip a character in the payload (middle segment) — this invalidates
    # the signature because it was computed over the original payload.
    payload = parts[1]
    tampered = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    parts[1] = tampered
    return ".".join(parts)


@pytest_asyncio.fixture
def wrong_tenant_token(app, test_tenant, second_tenant, test_user) -> str:
    """Token signed with a different tenant ID (tid mismatch)."""
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=15)
    return _sign_token(app, test_user.id, second_tenant.id, expires_at)


# ---------------------------------------------------------------------------
# Header fixtures (convenience combinations)
# ---------------------------------------------------------------------------


@pytest.fixture
def auth_headers(test_tenant, auth_token) -> dict[str, str]:
    """Headers with a valid Bearer token and tenant ID."""
    return {
        "Authorization": f"Bearer {auth_token}",
        "X-Tenant-ID": str(test_tenant.id),
    }


@pytest.fixture
def admin_headers(test_tenant, admin_token) -> dict[str, str]:
    """Headers with a valid admin Bearer token and tenant ID."""
    return {
        "Authorization": f"Bearer {admin_token}",
        "X-Tenant-ID": str(test_tenant.id),
    }


@pytest.fixture
def no_auth_headers(test_tenant) -> dict[str, str]:
    """Headers with only the tenant ID — no Authorization."""
    return {"X-Tenant-ID": str(test_tenant.id)}


@pytest.fixture
def expired_headers(test_tenant, expired_token) -> dict[str, str]:
    """Headers with an expired Bearer token."""
    return {
        "Authorization": f"Bearer {expired_token}",
        "X-Tenant-ID": str(test_tenant.id),
    }


@pytest.fixture
def tampered_headers(test_tenant, tampered_token) -> dict[str, str]:
    """Headers with a tampered Bearer token."""
    return {
        "Authorization": f"Bearer {tampered_token}",
        "X-Tenant-ID": str(test_tenant.id),
    }


@pytest.fixture
def inactive_headers(test_tenant, inactive_token) -> dict[str, str]:
    """Headers with a token for a deactivated user."""
    return {
        "Authorization": f"Bearer {inactive_token}",
        "X-Tenant-ID": str(test_tenant.id),
    }


@pytest.fixture
def wrong_tenant_headers(test_tenant, wrong_tenant_token) -> dict[str, str]:
    """Headers where the token's tid does not match the X-Tenant-ID."""
    return {
        "Authorization": f"Bearer {wrong_tenant_token}",
        "X-Tenant-ID": str(test_tenant.id),
    }


@pytest.fixture
def unknown_tenant_headers() -> dict[str, str]:
    """Headers with a non-existent tenant UUID."""
    return {"X-Tenant-ID": str(uuid4())}
