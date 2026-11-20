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

"""OpenID Connect endpoints — discovery and userinfo."""

from fastapi import APIRouter, Depends, Request

from app.core.tenant_context import TenantContext
from app.deps import get_discovery_service, get_tenant, get_token_service
from app.schemas.oidc import DiscoveryDocument, UserInfoResponse
from app.services.discovery_service import DiscoveryService
from app.services.token_service import TokenService

router = APIRouter()


@router.get("/.well-known/openid-configuration")
async def discovery_document(
    svc: DiscoveryService = Depends(get_discovery_service),
) -> DiscoveryDocument:
    """Return the OIDC discovery document for the current issuer."""
    return svc.get_document()


@router.get("/userinfo")
async def userinfo(
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
    token_svc: TokenService = Depends(get_token_service),
) -> UserInfoResponse:
    """Return claims about the authenticated end-user.

    Requires a valid Bearer token in the Authorization header.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        from app.core.exceptions import UnauthorizedError

        raise UnauthorizedError(detail="Missing Bearer token.")

    token = auth_header[7:]
    claims = await token_svc.validate_access_token(token, tenant.tenant_id)
    if claims is None:
        from app.core.exceptions import UnauthorizedError

        raise UnauthorizedError(detail="Invalid or expired token.")

    return UserInfoResponse(
        sub=claims.get("sub", ""),
        email=claims.get("email"),
        name=claims.get("name"),
    )
