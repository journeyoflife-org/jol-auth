"""JOL Auth — FastAPI application entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import admin, health, jwks, mfa, oauth, oidc, sessions, tenants, users
from app.config import settings
from app.middleware.audit_context import AuditContextMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.tenant_resolution import TenantResolutionMiddleware
from app.security.jwks_provider import JWKSProvider
from app.security.jwt_signing import JWTSigner
from app.security.key_manager import KeyManager
from app.telemetry import setup_telemetry


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown hooks."""
    # Startup
    setup_telemetry(app)

    # Initialise security singletons
    km = KeyManager()
    if settings.jwks_private_key_path and settings.jwks_public_key_path:
        km.load_from_files(settings.jwks_private_key_path, settings.jwks_public_key_path)
    else:
        km.generate_key_pair()
    app.state.key_manager = km
    app.state.jwt_signer = JWTSigner(km, settings.jwt_issuer, settings.jwt_audience)
    app.state.jwks_provider = JWKSProvider(km)

    yield
    # Shutdown


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="JOL Auth",
        description="Authentication and identity management for Journey Of Life.",
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Middleware (outermost first)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TenantResolutionMiddleware)
    app.add_middleware(AuditContextMiddleware)

    # Routers
    app.include_router(health.router, tags=["health"])
    app.include_router(oauth.router, prefix="/api/oauth", tags=["oauth"])
    app.include_router(oidc.router, prefix="/api/oidc", tags=["oidc"])
    app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
    app.include_router(tenants.router, prefix="/api/tenants", tags=["tenants"])
    app.include_router(users.router, prefix="/api/users", tags=["users"])
    app.include_router(mfa.router, prefix="/api/mfa", tags=["mfa"])
    app.include_router(admin.router, prefix="/api/admin", tags=["admin"])
    app.include_router(jwks.router, prefix="/api/jwks", tags=["jwks"])

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.app_host, port=settings.app_port, reload=True)
