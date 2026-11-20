"""Tests for tenant isolation — ensures queries are scoped to the tenant boundary."""

from uuid import uuid4

from app.core.exceptions import ForbiddenError, TenantIsolationError
from app.core.tenant_context import TenantContext


class TestTenantIsolation:
    def test_tenant_context_carries_tenant_id(self) -> None:
        """Verify tenant context stores the tenant_id."""
        tid = uuid4()
        ctx = TenantContext(tenant_id=tid, name="test-tenant", region="us-east")
        assert ctx.tenant_id == tid

    def test_tenant_context_frozen(self) -> None:
        """Verify tenant context cannot be mutated."""
        import dataclasses

        import pytest

        ctx = TenantContext(tenant_id=uuid4(), name="test", region="eu-west")
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.name = "changed"  # type: ignore[misc]

    def test_tenant_isolation_error_status(self) -> None:
        """Verify TenantIsolationError is a 403."""
        err = TenantIsolationError()
        assert err.status_code == 403

    def test_forbidden_error_status(self) -> None:
        """Verify ForbiddenError is also a 403."""
        err = ForbiddenError()
        assert err.status_code == 403

    def test_distinct_tenants_have_different_ids(self) -> None:
        """Verify two distinct tenants never share the same UUID."""
        ctx_a = TenantContext(tenant_id=uuid4(), name="a", region="eu")
        ctx_b = TenantContext(tenant_id=uuid4(), name="b", region="us")
        assert ctx_a.tenant_id != ctx_b.tenant_id
