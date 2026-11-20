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

"""Unit tests for MFA secret encryption and recovery codes.

Tests verify that:
- TOTP secrets can be encrypted and decrypted round-trip
- Different secrets produce different ciphertexts
- Wrong key raises SecretEncryptionError
- Recovery codes are generated with the correct format
- Recovery code hashing is deterministic
"""

import base64
import secrets

import pytest
from app.security.secret_encryption import (
    SecretEncryptionError,
    SecretEncryptor,
    generate_recovery_codes,
    hash_recovery_code,
)
from cryptography.fernet import Fernet


@pytest.fixture
def encryptor():
    """Create an encryptor with a test key."""
    key = Fernet.generate_key()
    return SecretEncryptor(key=key)


class TestSecretEncryptor:
    """Tests for AES-256-GCM secret encryption."""

    def test_encrypt_decrypt_roundtrip(self, encryptor):
        """Encrypted secrets should decrypt back to the original."""
        secret = base64.b32encode(secrets.token_bytes(10)).decode()  # generated TOTP base32 secret
        ciphertext = encryptor.encrypt(secret)
        plaintext = encryptor.decrypt(ciphertext)

        assert plaintext == secret
        assert ciphertext != secret  # Ciphertext must differ from plaintext

    def test_different_secrets_produce_different_ciphertexts(self, encryptor):
        """Different plaintexts must produce different ciphertexts."""
        ct1 = encryptor.encrypt("SECRET_ONE")
        ct2 = encryptor.encrypt("SECRET_TWO")

        assert ct1 != ct2

    def test_same_secret_produces_different_ciphertexts(self, encryptor):
        """Same plaintext encrypted twice must produce different ciphertexts (random IV)."""
        ct1 = encryptor.encrypt("SAME_SECRET")
        ct2 = encryptor.encrypt("SAME_SECRET")

        assert ct1 != ct2  # Fernet uses random IV

    def test_wrong_key_raises_error(self):
        """Decryption with the wrong key should raise SecretEncryptionError."""
        enc1 = SecretEncryptor(key=Fernet.generate_key())
        enc2 = SecretEncryptor(key=Fernet.generate_key())

        ciphertext = enc1.encrypt("MY_SECRET")

        with pytest.raises(SecretEncryptionError):
            enc2.decrypt(ciphertext)

    def test_tampered_ciphertext_raises_error(self, encryptor):
        """Tampered ciphertext should raise SecretEncryptionError."""
        ciphertext = encryptor.encrypt("MY_SECRET")
        # Tamper with the ciphertext
        tampered = ciphertext[:-5] + "XXXXX"

        with pytest.raises(SecretEncryptionError):
            encryptor.decrypt(tampered)

    def test_key_rotation(self, encryptor):
        """Key rotation should re-encrypt secrets with the new key."""
        old_encryptor = encryptor
        new_encryptor = SecretEncryptor(key=Fernet.generate_key())

        plaintext = "ROTATION_TEST_SECRET"
        old_ciphertext = old_encryptor.encrypt(plaintext)

        # Rotate to new key
        new_ciphertext = new_encryptor.rotate_key(old_encryptor, old_ciphertext)

        # New key should decrypt successfully
        assert new_encryptor.decrypt(new_ciphertext) == plaintext

        # Old key should NOT decrypt the new ciphertext
        with pytest.raises(SecretEncryptionError):
            old_encryptor.decrypt(new_ciphertext)

    def test_missing_key_raises_error(self, monkeypatch):
        """Missing MFA_ENCRYPTION_KEY should raise SecretEncryptionError."""
        monkeypatch.delenv("MFA_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("MFA_ENCRYPTION_KEY_FILE", raising=False)
        monkeypatch.setattr("app.config.settings.mfa_encryption_key", "")

        with pytest.raises(SecretEncryptionError, match="MFA_ENCRYPTION_KEY not set"):
            SecretEncryptor()


class TestRecoveryCodes:
    """Tests for MFA recovery code generation."""

    def test_generates_correct_count(self):
        """Should generate the requested number of codes."""
        codes = generate_recovery_codes(count=10)
        assert len(codes) == 10

    def test_code_format(self):
        """Codes should be formatted as XXXX-XXXX-XXXX-XXXX-XXXX."""
        codes = generate_recovery_codes(count=1)
        parts = codes[0].split("-")
        assert len(parts) == 5
        for part in parts:
            assert len(part) == 4

    def test_codes_are_unique(self):
        """All generated codes should be unique."""
        codes = generate_recovery_codes(count=100)
        assert len(set(codes)) == 100

    def test_hash_is_deterministic(self):
        """Same code should produce the same hash."""
        code = "ABCD-1234-EFGH-5678-IJKL"
        hash1 = hash_recovery_code(code)
        hash2 = hash_recovery_code(code)

        assert hash1 == hash2

    def test_hash_is_one_way(self):
        """Hash should not equal the original code."""
        code = "ABCD-1234-EFGH-5678-IJKL"
        hashed = hash_recovery_code(code)

        assert hashed != code
        assert len(hashed) == 64  # SHA-256 hex
