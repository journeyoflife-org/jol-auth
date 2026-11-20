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

"""Key manager — RSA key pair lifecycle, rotation, and storage.

Manages RS256 signing keys with support for scheduled and emergency rotation.
Maintains a key history (current + one previous) so that tokens signed with
the previous key remain verifiable during the overlap period.
"""

import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class KeyPair:
    """Immutable record of a single RSA key pair."""

    kid: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


class KeyManager:
    """Manages RSA signing keys with rotation support.

    Keeps the current signing key and at most one previous key (for the
    overlap period).  All public keys are accessible via :pymethod:`all_keys`
    so that the JWKS endpoint can publish them for token verification.
    """

    def __init__(self) -> None:
        self._current: KeyPair | None = None
        self._previous: KeyPair | None = None

    # -- Key lifecycle -------------------------------------------------------

    def generate_key_pair(self, key_size: int = 2048) -> str:
        """Generate a new RSA key pair and make it the current signing key.

        Returns the newly assigned ``kid``.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        kid = str(uuid.uuid4())
        new_pair = KeyPair(kid=kid, private_key=private_key, public_key=private_key.public_key())

        # Move current to previous for the overlap window
        self._previous = self._current
        self._current = new_pair
        return kid

    def load_from_files(self, private_key_path: str, public_key_path: str) -> str:
        """Load an existing PEM key pair from disk and make it current.

        Returns the assigned ``kid``.
        """
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Private key is not RSA.")
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Public key is not RSA.")

        kid = str(uuid.uuid4())
        new_pair = KeyPair(kid=kid, private_key=private_key, public_key=public_key)
        self._previous = self._current
        self._current = new_pair
        return kid

    def rotate(self, key_size: int = 2048) -> str:
        """Rotate keys: generate a new pair, retire the current one.

        Returns the new ``kid``.  The previous key remains available for
        verification until the next rotation.
        """
        return self.generate_key_pair(key_size)

    # -- Accessors -----------------------------------------------------------

    def get_private_key(self) -> rsa.RSAPrivateKey:
        """Return the current signing private key.

        Raises ``RuntimeError`` if no key has been generated or loaded.
        """
        if self._current is None:
            raise RuntimeError("No signing key available. Call generate_key_pair() or load_from_files() first.")
        return self._current.private_key

    def get_public_key(self) -> rsa.RSAPublicKey:
        """Return the current verification public key.

        Raises ``RuntimeError`` if no key has been generated or loaded.
        """
        if self._current is None:
            raise RuntimeError("No signing key available. Call generate_key_pair() or load_from_files() first.")
        return self._current.public_key

    @property
    def kid(self) -> str:
        """Return the current key ID."""
        if self._current is None:
            raise RuntimeError("No signing key available.")
        return self._current.kid

    def get_key_by_kid(self, kid: str) -> KeyPair | None:
        """Return the key pair matching *kid*, or ``None`` if not found.

        Checks both the current and previous keys.
        """
        if self._current and self._current.kid == kid:
            return self._current
        if self._previous and self._previous.kid == kid:
            return self._previous
        return None

    def all_keys(self) -> list[KeyPair]:
        """Return all available key pairs (current and previous)."""
        keys: list[KeyPair] = []
        if self._current:
            keys.append(self._current)
        if self._previous:
            keys.append(self._previous)
        return keys
