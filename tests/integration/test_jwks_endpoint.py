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
