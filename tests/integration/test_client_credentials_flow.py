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
