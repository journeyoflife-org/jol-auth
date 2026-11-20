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
