"""OAuth client schemas for API request/response validation."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ClientCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    redirect_uris: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=lambda: ["authorization_code"])
    scopes: list[str] = Field(default_factory=lambda: ["openid"])


class ClientResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    client_id: str
    name: str
    redirect_uris: str
    grant_types: str
    scopes: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
