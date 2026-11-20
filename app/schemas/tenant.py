"""Tenant schemas for API request/response validation."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class TenantCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    region: str = Field(..., min_length=2, max_length=16)


class TenantUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    is_active: bool | None = None


class TenantResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    region: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
