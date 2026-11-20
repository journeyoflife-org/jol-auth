"""JWKS (JSON Web Key Set) endpoint."""

from typing import Any

from fastapi import APIRouter, Depends

from app.deps import get_jwks_provider
from app.security.jwks_provider import JWKSProvider

router = APIRouter()


@router.get("/")
async def get_jwks(
    provider: JWKSProvider = Depends(get_jwks_provider),
) -> dict[str, Any]:
    """Return the public JWKS document for token verification."""
    return provider.get_jwks()
