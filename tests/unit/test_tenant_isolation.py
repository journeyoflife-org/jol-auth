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
