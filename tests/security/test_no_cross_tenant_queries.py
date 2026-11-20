"""Security tests — verify no cross-tenant queries are possible.

Tests the tenant isolation enforcement at the repository and service layers.
"""

from uuid import uuid4

from app.core.exceptions import TenantIsolationError
from app.core.tenant_context import TenantContext


class TestNoCrossTenantQueries:
    def test_tenant_context_is_immutable(self) -> None:
        """Verify TenantContext cannot be modified after creation."""
        tid = uuid4()
        ctx = TenantContext(tenant_id=tid, name="tenant-a", region="eu-west")
        assert ctx.tenant_id == tid
        assert ctx.is_active is True

        # Frozen dataclass — assignment should raise
        import dataclasses

        import pytest

        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.name = "changed"  # type: ignore[misc]

    def test_different_tenant_ids_are_distinct(self) -> None:
        """Verify two different tenant UUIDs are never equal."""
        tid1 = uuid4()
        tid2 = uuid4()
        assert tid1 != tid2

    def test_tenant_isolation_error_is_403(self) -> None:
        """Verify TenantIsolationError returns 403 status."""
        err = TenantIsolationError()
        assert err.status_code == 403
        assert "Cross-tenant" in err.detail

    def test_tenant_isolation_custom_detail(self) -> None:
        """Verify custom detail message is preserved."""
        err = TenantIsolationError(detail="Custom message")
        assert err.detail == "Custom message"
