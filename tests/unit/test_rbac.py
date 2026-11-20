"""Tests for RBAC enforcer — permission checks within a tenant boundary."""

from uuid import uuid4

from app.core.rbac import Permission, RBACEnforcer, Role
from app.core.tenant_context import TenantContext


class TestRBAC:
    def setup_method(self) -> None:
        self.tenant = TenantContext(tenant_id=uuid4(), name="test", region="eu-west")
        self.enforcer = RBACEnforcer(tenant=self.tenant)

    def test_has_permission_returns_true_for_matching_permission(self) -> None:
        role = Role(name="admin", permissions=[Permission(resource="users", action="create")])
        assert self.enforcer.has_permission(role, "users", "create") is True

    def test_has_permission_returns_false_for_non_matching_permission(self) -> None:
        role = Role(name="viewer", permissions=[Permission(resource="users", action="read")])
        assert self.enforcer.has_permission(role, "users", "delete") is False

    def test_require_permission_raises_for_missing_permission(self) -> None:
        import pytest
        from app.core.exceptions import ForbiddenError

        role = Role(name="viewer", permissions=[])
        with pytest.raises(ForbiddenError):
            self.enforcer.require_permission(role, "tenants", "update")

    def test_empty_permissions_denies_all(self) -> None:
        role = Role(name="guest", permissions=[])
        assert self.enforcer.has_permission(role, "anything", "any_action") is False
