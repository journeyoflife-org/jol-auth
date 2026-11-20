"""Security utilities — hashing, encryption, and constant-time comparison.

Provides Argon2id password hashing (OWASP-recommended), token generation,
SHA-256 helpers, and constant-time comparison.
"""

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

# Argon2id with OWASP-recommended parameters
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID,
)


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random hex token."""
    return secrets.token_hex(length)


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def sha256_hex(value: str) -> str:
    """Return the SHA-256 hex digest of the input string."""
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password: str) -> str:
    """Hash a password using Argon2id.

    The returned string includes the salt and parameters, ready for
    verification with :func:`verify_password`.
    """
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against an Argon2id hash.

    Returns ``True`` on match, ``False`` on mismatch.  Never raises on
    a simple mismatch.
    """
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
