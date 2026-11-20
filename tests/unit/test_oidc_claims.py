"""Unit tests for OIDC ID token claims and compliance.

Tests verify that:
- ID token claims include all required OIDC standard claims
- nonce is included when provided
- auth_time, acr, amr claims are set correctly
- at_hash is computed correctly
- UserInfo claims are scope-filtered
- Discovery document advertises all required claims
"""

import base64
import hashlib
import secrets
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.security.oidc_claims import (
    SCOPE_CLAIMS_MAP,
    build_id_token_claims,
    build_userinfo_claims,
    get_claims_for_scopes,
)


@pytest.fixture
def test_user():
    """Test user record."""
    return {
        "id": uuid4(),
        "email": "test@jol.org",
        "display_name": "Test User",
        "email_verified": True,
    }


@pytest.fixture
def test_issuer():
    return "https://auth.journeyoflife.org"


@pytest.fixture
def test_client_id():
    return "test-client-123"


class TestIDTokenClaims:
    """Tests for OIDC ID token claim building."""

    def test_required_claims_present(self, test_user, test_issuer, test_client_id):
        """ID token must contain iss, sub, aud, iat, exp per OIDC Core §2."""
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
        )

        assert "iss" in claims
        assert "sub" in claims
        assert "aud" in claims
        assert "iat" in claims
        assert "exp" in claims

        assert claims["iss"] == test_issuer
        assert claims["aud"] == test_client_id
        assert claims["sub"] == str(test_user["id"])

    def test_nonce_included_when_provided(self, test_user, test_issuer, test_client_id):
        """nonce must be in ID token when provided in auth request."""
        nonce = "test-nonce-abc123"
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
            nonce=nonce,
        )

        assert claims["nonce"] == nonce

    def test_auth_time_set(self, test_user, test_issuer, test_client_id):
        """auth_time should be set when provided."""
        auth_time = int(datetime.now(tz=UTC).timestamp())
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
            auth_time=auth_time,
        )

        assert claims["auth_time"] == auth_time

    def test_acr_claim_set(self, test_user, test_issuer, test_client_id):
        """acr (Authentication Context Class Reference) should be set."""
        acr = "urn:mace:incommon:iap:silver"
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
            acr=acr,
        )

        assert claims["acr"] == acr

    def test_amr_claim_set(self, test_user, test_issuer, test_client_id):
        """amr (Authentication Methods References) should be set."""
        amr = ["pwd", "otp"]
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
            amr=amr,
        )

        assert claims["amr"] == amr

    def test_at_hash_computed_correctly(self, test_user, test_issuer, test_client_id):
        """at_hash should be the base64url-encoded leftmost half of SHA-256(access_token)."""
        access_token = secrets.token_urlsafe(32)  # generated synthetic token; hash derived below
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
            access_token=access_token,
        )

        # Verify the at_hash
        digest = hashlib.sha256(access_token.encode()).digest()
        expected_hash = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()

        assert claims["at_hash"] == expected_hash

    def test_exp_is_in_the_future(self, test_user, test_issuer, test_client_id):
        """exp should be in the future (ID tokens are short-lived)."""
        now = int(datetime.now(tz=UTC).timestamp())
        claims = build_id_token_claims(
            user=test_user,
            issuer=test_issuer,
            audience=test_client_id,
        )

        assert claims["exp"] > now
        assert claims["exp"] <= now + 900  # Max 15 minutes


class TestUserInfoClaims:
    """Tests for OIDC UserInfo claim extraction."""

    def test_sub_always_present(self, test_user):
        """sub must always be in UserInfo response per OIDC Core §5.1."""
        claims = build_userinfo_claims(test_user)
        assert "sub" in claims
        assert claims["sub"] == str(test_user["id"])

    def test_profile_scope_claims(self, test_user):
        """profile scope should return name and preferred_username."""
        claims = build_userinfo_claims(test_user, requested_scopes=["openid", "profile"])
        assert claims.get("name") == "Test User"
        assert claims.get("preferred_username") == "test@jol.org"

    def test_email_scope_claims(self, test_user):
        """email scope should return email and email_verified."""
        claims = build_userinfo_claims(test_user, requested_scopes=["openid", "email"])
        assert claims.get("email") == "test@jol.org"
        assert claims.get("email_verified") is True

    def test_no_profile_claims_without_scope(self, test_user):
        """Without profile scope, name should not be present."""
        claims = build_userinfo_claims(test_user, requested_scopes=["openid"])
        assert "name" not in claims
        assert "email" not in claims


class TestScopeClaimsMap:
    """Tests for the scope-to-claims mapping."""

    def test_openid_scope_has_no_extra_claims(self):
        """openid scope should map to empty list (it just triggers ID token)."""
        assert SCOPE_CLAIMS_MAP["openid"] == []

    def test_profile_scope_includes_name(self):
        """profile scope should include name claim."""
        assert "name" in SCOPE_CLAIMS_MAP["profile"]

    def test_email_scope_includes_email(self):
        """email scope should include email claim."""
        assert "email" in SCOPE_CLAIMS_MAP["email"]

    def test_get_claims_for_scopes_deduplicates(self):
        """get_claims_for_scopes should return unique claims."""
        claims = get_claims_for_scopes(["openid", "profile", "email"])
        assert "sub" in claims
        assert "name" in claims
        assert "email" in claims
        # Check no duplicates
        assert len(claims) == len(set(claims))
