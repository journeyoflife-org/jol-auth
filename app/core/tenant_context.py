"""Tenant context — carries resolved tenant identity through the request lifecycle."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class TenantContext:
    """Immutable snapshot of the resolved tenant for a single request."""

    tenant_id: UUID
    name: str
    region: str
    is_active: bool = True
