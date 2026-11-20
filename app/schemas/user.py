"""User schemas for API request/response validation."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    display_name: str | None = Field(None, max_length=255)


class UserUpdate(BaseModel):
    display_name: str | None = Field(None, max_length=255)
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    email: str
    display_name: str | None
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
