"""OIDC schemas for discovery and userinfo responses."""

from pydantic import BaseModel


class DiscoveryDocument(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    registration_endpoint: str | None = None
    scopes_supported: list[str]
    response_types_supported: list[str]
    grant_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    claims_supported: list[str]
    code_challenge_methods_supported: list[str]


class UserInfoResponse(BaseModel):
    sub: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    preferred_username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    locale: str | None = None
    updated_at: int | None = None
