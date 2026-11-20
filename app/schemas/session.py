"""Session schemas for API request/response validation."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class SessionResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    user_id: UUID
    ip_address: str | None
    user_agent: str | None
    last_activity: datetime
    expires_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}
