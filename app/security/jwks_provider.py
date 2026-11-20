"""JWKS provider — serves the public key set in JWK format (RFC 7517).

Publishes all available public keys (current + previous during rotation)
so that downstream services can verify token signatures.
"""

from __future__ import annotations

from typing import Any

from app.security.key_manager import KeyManager, KeyPair


class JWKSProvider:
    """Provides the JWKS (JSON Web Key Set) document."""

    def __init__(self, key_manager: KeyManager) -> None:
        self._key_manager = key_manager

    def get_jwks(self) -> dict[str, Any]:
        """Export all available public keys as a JWKS document.

        Returns a dict suitable for JSON serialisation with the structure::

            {"keys": [{"kty": "RSA", "kid": "...", "n": "...", "e": "...", ...}]}
        """
        keys: list[dict[str, Any]] = []
        for key_pair in self._key_manager.all_keys():
            jwk = self._key_pair_to_jwk(key_pair)
            keys.append(jwk)
        return {"keys": keys}

    @staticmethod
    def _key_pair_to_jwk(key_pair: KeyPair) -> dict[str, Any]:
        """Convert an RSA key pair to a JWK dict."""
        public_numbers = key_pair.public_key.public_numbers()
        return {
            "kty": "RSA",
            "kid": key_pair.kid,
            "use": "sig",
            "alg": "RS256",
            "n": _int_to_base64url(public_numbers.n, public_numbers.n.bit_length()),
            "e": _int_to_base64url(public_numbers.e, public_numbers.e.bit_length()),
        }


def _int_to_base64url(value: int, bit_length: int) -> str:
    """Encode a non-negative integer as base64url (no padding)."""
    import base64

    byte_length = (bit_length + 7) // 8
    raw = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
