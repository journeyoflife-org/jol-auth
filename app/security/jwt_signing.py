"""JWT signing — creation and verification of signed JWTs.

All tokens are signed with RS256 and include standard registered claims
(``iss``, ``aud``, ``iat``, ``exp``, ``jti``) plus the ``kid`` header.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import jwt

from app.security.key_manager import KeyManager


class JWTSigner:
    """Sign and verify JWTs using the key manager.

    Tokens are rejected if:
    - The signature does not verify against any known key.
    - The ``iss`` or ``aud`` claims do not match the configured values.
    - The token is expired.
    """

    def __init__(self, key_manager: KeyManager, issuer: str, audience: str) -> None:
        self._key_manager = key_manager
        self._issuer = issuer
        self._audience = audience

    def sign(self, claims: dict[str, Any], expires_at: datetime) -> str:
        """Create and sign a JWT with the given claims.

        Automatically injects ``iss``, ``aud``, ``iat``, ``exp``, ``jti``,
        and sets the ``kid`` in the JOSE header.
        """
        now = datetime.now(tz=UTC)
        payload: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid.uuid4()),
            **claims,
        }
        kid = self._key_manager.kid
        private_key = self._key_manager.get_private_key()
        return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    def verify(self, token: str) -> dict[str, Any]:
        """Verify signature and standard claims, returning the decoded payload.

        Tries all known keys (current + previous) to support the rotation
        overlap window.

        Raises:
            jwt.InvalidTokenError: On any verification failure.
        """
        # Decode header to find the kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if kid:
            key_pair = self._key_manager.get_key_by_kid(kid)
            if key_pair is None:
                raise jwt.InvalidKeyError(f"Unknown kid: {kid}")
            public_key = key_pair.public_key
        else:
            # Fallback: try the current key
            public_key = self._key_manager.get_public_key()

        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=self._issuer,
            audience=self._audience,
            options={"require": ["iss", "aud", "exp", "iat"]},
        )
