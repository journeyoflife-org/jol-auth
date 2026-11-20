"""Integration tests for the JWKS endpoint."""

from app.security.jwks_provider import JWKSProvider
from app.security.key_manager import KeyManager


class TestJWKSEndpoint:
    def test_jwks_returns_valid_key_set(self) -> None:
        """Verify JWKS response contains keys with required fields."""
        km = KeyManager()
        km.generate_key_pair()
        provider = JWKSProvider(km)

        jwks = provider.get_jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1

        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key

    def test_jwks_contains_signing_key(self) -> None:
        """Verify the current signing key is present in the set."""
        km = KeyManager()
        kid = km.generate_key_pair()
        provider = JWKSProvider(km)

        jwks = provider.get_jwks()
        kids = [k["kid"] for k in jwks["keys"]]
        assert kid in kids

    def test_jwks_after_rotation(self) -> None:
        """Verify both old and new keys are present after rotation."""
        km = KeyManager()
        kid1 = km.generate_key_pair()
        kid2 = km.rotate()
        provider = JWKSProvider(km)

        jwks = provider.get_jwks()
        kids = [k["kid"] for k in jwks["keys"]]
        assert kid1 in kids
        assert kid2 in kids
        assert len(jwks["keys"]) == 2

    def test_jwks_empty_before_key_generation(self) -> None:
        """Verify JWKS has no keys before generation."""
        km = KeyManager()
        provider = JWKSProvider(km)
        jwks = provider.get_jwks()
        assert jwks["keys"] == []
