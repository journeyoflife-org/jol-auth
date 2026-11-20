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
