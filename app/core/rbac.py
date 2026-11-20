# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
