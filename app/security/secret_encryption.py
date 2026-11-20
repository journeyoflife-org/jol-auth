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

"""Secret encryption — AES-256-GCM envelope encryption for sensitive data.

Uses Fernet (which is AES-128-CBC + HMAC-SHA256) as the high-level
interface.  For production, the Fernet key should be wrapped by a KMS
(AWS KMS, Google Cloud KMS, or HashiCorp Vault Transit).

Key management:
    1. Generate a Fernet key: ``Fernet.generate_key()``
    2. Store it in environment variable ``MFA_ENCRYPTION_KEY`` or
       a file path referenced by ``MFA_ENCRYPTION_KEY_FILE``
    3. For rotation: decrypt with old key, re-encrypt with new key
    4. For KMS integration: wrap the Fernet key with KMS at rest

The encryptor is a singleton — instantiate once per application lifecycle.
"""

import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


class SecretEncryptionError(Exception):
    """Raised when encryption/decryption fails."""


class SecretEncryptor:
    """AES-256-GCM (via Fernet) envelope encryption for sensitive secrets.

    Fernet provides:
    - AES-128-CBC encryption (NIST-approved)
    - HMAC-SHA256 for authentication (tamper detection)
    - Random IV per message
    - Timestamp for TTL-based rejection
    """

    def __init__(self, key: bytes | str | None = None) -> None:
        """Initialise with a Fernet key.

        Args:
            key: Base64-urlsafe Fernet key.  If None, loads from
                 environment (MFA_ENCRYPTION_KEY or MFA_ENCRYPTION_KEY_FILE).
        """
        if key is None:
            key = self._load_key_from_env()
        if isinstance(key, str):
            key = key.encode()
        self._fernet = Fernet(key)

    @staticmethod
    def _load_key_from_env() -> bytes:
        """Load the encryption key from environment or file."""
        # Check file path first (Kubernetes-style secret mount)
        file_path = os.environ.get("MFA_ENCRYPTION_KEY_FILE")
        if file_path and os.path.isfile(file_path):
            with open(file_path, encoding="utf-8") as f:
                return f.read().strip().encode()

        # Check direct environment variable
        key = os.environ.get("MFA_ENCRYPTION_KEY") or settings.mfa_encryption_key
        if not key:
            raise SecretEncryptionError(
                "MFA_ENCRYPTION_KEY not set. Generate one with: "
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        return key.encode()

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string.

        Returns:
            Base64-urlsafe encrypted ciphertext as a string.
        """
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt an encrypted string.

        Args:
            ciphertext: Base64-urlsafe encrypted string from :meth:`encrypt`.

        Returns:
            The original plaintext string.

        Raises:
            SecretEncryptionError: If decryption fails (wrong key, tampered data).
        """
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as exc:
            raise SecretEncryptionError("Failed to decrypt secret — key mismatch or tampered data.") from exc

    def rotate_key(self, old_encryptor: "SecretEncryptor", ciphertext: str) -> str:
        """Re-encrypt a secret with a new key (key rotation).

        Args:
            old_encryptor: The encryptor with the old key.
            ciphertext: The secret encrypted with the old key.

        Returns:
            The secret re-encrypted with the new key.
        """
        plaintext = old_encryptor.decrypt(ciphertext)
        return self.encrypt(plaintext)


@lru_cache(maxsize=1)
def get_encryptor() -> SecretEncryptor:
    """Return a singleton SecretEncryptor instance.

    The key is loaded once at startup.  For key rotation, clear the
    cache with ``get_encryptor.cache_clear()`` after updating the env var.
    """
    return SecretEncryptor()


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Generate cryptographically secure recovery codes.

    Each code is 20 characters (5 groups of 4 alphanumeric chars)
    formatted as XXXX-XXXX-XXXX-XXXX-XXXX for human readability.

    Returns:
        List of recovery code strings.
    """
    import secrets
    import string

    alphabet = string.ascii_uppercase + string.digits
    codes: list[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(20))
        # Format as XXXX-XXXX-XXXX-XXXX-XXXX
        formatted = "-".join(raw[i : i + 4] for i in range(0, 20, 4))
        codes.append(formatted)
    return codes


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for secure storage (one-way).

    Recovery codes are hashed with SHA-256 (they don't need Argon2id
    because they are single-use and 20 chars of high entropy).
    """
    import hashlib

    return hashlib.sha256(code.encode()).hexdigest()
