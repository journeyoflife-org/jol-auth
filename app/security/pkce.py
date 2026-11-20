"""PKCE (Proof Key for Code Exchange) — RFC 7636 implementation."""

import base64
import hashlib
import secrets


def generate_code_verifier(length: int = 64) -> str:
    """Generate a cryptographically random code verifier (43–128 characters)."""
    return secrets.token_urlsafe(length)[:128]


def generate_code_challenge(verifier: str, method: str = "S256") -> str:
    """Derive the code challenge from a verifier.

    Supports:
    - S256: SHA-256 hash, base64url-encoded (recommended)
    - plain: verifier == challenge (not recommended, included for conformance)
    """
    if method == "plain":
        return verifier
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    raise ValueError(f"Unsupported code_challenge_method: {method}")


def verify_code_challenge(verifier: str, challenge: str, method: str = "S256") -> bool:
    """Verify that a code verifier matches the expected challenge."""
    return generate_code_challenge(verifier, method) == challenge
