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

"""Security tests — verify token scopes are restricted to what the client is granted."""

import pytest
from app.core.exceptions import AuthError
from app.security.oauth_validators import validate_scope


class TestTokenScopeRestriction:
    def test_requested_scopes_intersect_client_scopes(self) -> None:
        """Verify issued token scopes are subset of client scopes."""
        result = validate_scope("openid profile email", "openid profile")
        assert set(result) == {"openid", "profile"}

    def test_elevation_of_privilege_via_scope_rejected(self) -> None:
        """Verify requesting admin scope as a regular client fails."""
        with pytest.raises(AuthError, match="No valid scopes"):
            validate_scope("admin superuser", "openid profile email")

    def test_empty_scope_intersection_rejected(self) -> None:
        """Verify request is rejected when no scopes match."""
        with pytest.raises(AuthError, match="No valid scopes"):
            validate_scope("custom-scope", "openid profile")

    def test_exact_scope_match_succeeds(self) -> None:
        """Verify exact scope match works."""
        result = validate_scope("openid", "openid profile email")
        assert result == ["openid"]

    def test_all_client_scopes_granted(self) -> None:
        """Verify requesting all client scopes returns all."""
        result = validate_scope("openid profile", "openid profile")
        assert set(result) == {"openid", "profile"}
