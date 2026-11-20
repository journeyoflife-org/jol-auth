"""MFA schemas for API request/response validation."""

from uuid import UUID

from pydantic import BaseModel, Field


class TOTPEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str
    issuer: str
    digits: int = 6
    period: int = 30


class TOTPVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)
    factor_id: UUID | None = None


class MFAFactorResponse(BaseModel):
    id: UUID
    factor_type: str
    is_verified: bool

    model_config = {"from_attributes": True}
