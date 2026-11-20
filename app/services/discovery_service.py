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

"""Discovery service — builds and serves the OIDC discovery document.

The discovery document advertises all supported OIDC features per
OpenID Connect Discovery 1.0 specification.
"""

from app.config import settings
from app.schemas.oidc import DiscoveryDocument


class DiscoveryService:
    def get_document(self) -> DiscoveryDocument:
        """Build the OIDC discovery document from application configuration."""
        base_url = settings.jwt_issuer
        return DiscoveryDocument(
            issuer=base_url,
            authorization_endpoint=f"{base_url}/api/oauth/authorize",
            token_endpoint=f"{base_url}/api/oauth/token",
            userinfo_endpoint=f"{base_url}/api/oidc/userinfo",
            jwks_uri=f"{base_url}/api/jwks/",
            scopes_supported=[
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
            ],
            response_types_supported=[
                "code",
                "id_token",
                "code id_token",
                "token id_token",
            ],
            grant_types_supported=[
                "authorization_code",
                "client_credentials",
                "refresh_token",
            ],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=[settings.jwt_signing_algorithm],
            token_endpoint_auth_methods_supported=[
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt",
            ],
            claims_supported=[
                # Standard claims
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "nonce",
                "auth_time",
                "acr",
                "amr",
                "at_hash",
                "c_hash",
                # Profile scope
                "name",
                "preferred_username",
                "given_name",
                "family_name",
                "middle_name",
                "nickname",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "updated_at",
                # Email scope
                "email",
                "email_verified",
                # Phone scope
                "phone_number",
                "phone_number_verified",
            ],
            code_challenge_methods_supported=["S256"],
        )
