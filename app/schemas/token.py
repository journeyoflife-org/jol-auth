"""Token schemas for API request/response validation."""

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str = "openid"


class TokenIntrospectionResponse(BaseModel):
    active: bool
    scope: str | None = None
    client_id: str | None = None
    sub: str | None = None
    iss: str | None = None
    exp: int | None = None
    iat: int | None = None
    token_type: str | None = None


class TokenRevocationRequest(BaseModel):
    token: str
    token_type_hint: str | None = None
