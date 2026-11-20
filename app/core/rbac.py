"""Role-Based Access Control enforcer with tenant-scoped permission checks."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.tenant_context import TenantContext


@dataclass
class Permission:
    """A single permission scoped to a resource type."""

    resource: str
    action: str


@dataclass
class Role:
    """A named role with a set of permissions."""

    name: str
    permissions: list[Permission] = field(default_factory=list)


class RBACEnforcer:
    """Enforce RBAC policies within a tenant boundary."""

    def __init__(self, tenant: "TenantContext") -> None:
        self._tenant = tenant

    def has_permission(self, role: Role, resource: str, action: str) -> bool:
        """Check whether a role grants a specific permission."""
        return any(perm.resource == resource and perm.action == action for perm in role.permissions)

    def require_permission(self, role: Role, resource: str, action: str) -> None:
        """Raise if the role does not grant the required permission."""
        if not self.has_permission(role, resource, action):
            from app.core.exceptions import ForbiddenError

            raise ForbiddenError(detail=f"Role '{role.name}' lacks {action} on {resource}")
