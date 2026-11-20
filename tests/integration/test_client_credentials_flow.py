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

"""Integration tests for the client credentials flow.

Exercises the client validation and scope intersection logic.
"""

import pytest
from app.security.oauth_validators import validate_grant_type, validate_scope


class TestClientCredentialsFlow:
    def test_valid_scope_intersection(self) -> None:
        """Verify scope intersection returns valid subset."""
        result = validate_scope("openid profile", "openid profile email")
        assert set(result) == {"openid", "profile"}

    def test_no_valid_scopes_raises(self) -> None:
        """Verify requesting no valid scopes is rejected."""
        from app.core.exceptions import AuthError

        with pytest.raises(AuthError, match="No valid scopes"):
            validate_scope("admin", "openid profile")

    def test_valid_grant_type_accepted(self) -> None:
        """Verify allowed grant type passes validation."""
        validate_grant_type("client_credentials", ["authorization_code", "client_credentials"])

    def test_invalid_grant_type_rejected(self) -> None:
        """Verify disallowed grant type is rejected."""
        from app.core.exceptions import AuthError

        with pytest.raises(AuthError, match="Unsupported grant_type"):
            validate_grant_type("password", ["authorization_code", "client_credentials"])

    def test_scope_subset_enforced(self) -> None:
        """Verify only permitted scopes are returned."""
        result = validate_scope("openid profile email admin", "openid email")
        assert set(result) == {"openid", "email"}
