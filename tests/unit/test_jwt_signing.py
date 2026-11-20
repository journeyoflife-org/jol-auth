"""Tests for JWT signing — sign/verify round-trip, expiry, and kid handling."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from app.security.jwt_signing import JWTSigner
from app.security.key_manager import KeyManager


def _make_signer() -> JWTSigner:
    km = KeyManager()
    km.generate_key_pair()
    return JWTSigner(km, issuer="https://auth.test", audience="https://api.test")


class TestJWTSigning:
    def test_sign_verify_round_trip(self) -> None:
        signer = _make_signer()
        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token = signer.sign({"sub": "user-123"}, expires)

        claims = signer.verify(token)
        assert claims["sub"] == "user-123"
        assert claims["iss"] == "https://auth.test"
        assert claims["aud"] == "https://api.test"
        assert "jti" in claims

    def test_expired_token_raises(self) -> None:
        signer = _make_signer()
        expires = datetime.now(tz=UTC) - timedelta(minutes=1)
        token = signer.sign({"sub": "user-123"}, expires)

        with pytest.raises(jwt.ExpiredSignatureError):
            signer.verify(token)

    def test_wrong_issuer_rejected(self) -> None:
        km = KeyManager()
        km.generate_key_pair()
        signer_a = JWTSigner(km, issuer="https://a.test", audience="https://api.test")
        signer_b = JWTSigner(km, issuer="https://b.test", audience="https://api.test")

        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token = signer_a.sign({}, expires)

        with pytest.raises(jwt.InvalidIssuerError):
            signer_b.verify(token)

    def test_wrong_audience_rejected(self) -> None:
        km = KeyManager()
        km.generate_key_pair()
        signer_a = JWTSigner(km, issuer="https://auth.test", audience="https://api-a.test")
        signer_b = JWTSigner(km, issuer="https://auth.test", audience="https://api-b.test")

        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token = signer_a.sign({}, expires)

        with pytest.raises(jwt.InvalidAudienceError):
            signer_b.verify(token)

    def test_kid_in_header(self) -> None:
        signer = _make_signer()
        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token = signer.sign({}, expires)

        header = jwt.get_unverified_header(token)
        assert "kid" in header
        assert header["kid"] == signer._key_manager.kid

    def test_verify_after_rotation_uses_previous_key(self) -> None:
        km = KeyManager()
        km.generate_key_pair()
        signer = JWTSigner(km, issuer="https://auth.test", audience="https://api.test")

        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token_before = signer.sign({"v": 1}, expires)

        # Rotate
        km.rotate()

        # Old token should still verify using previous key
        claims = signer.verify(token_before)
        assert claims["v"] == 1

    def test_unknown_kid_rejected(self) -> None:
        km1 = KeyManager()
        km1.generate_key_pair()
        km2 = KeyManager()
        km2.generate_key_pair()

        signer1 = JWTSigner(km1, issuer="https://auth.test", audience="https://api.test")
        signer2 = JWTSigner(km2, issuer="https://auth.test", audience="https://api.test")

        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token = signer1.sign({}, expires)

        with pytest.raises(jwt.InvalidKeyError, match="Unknown kid"):
            signer2.verify(token)

    def test_tampered_token_rejected(self) -> None:
        signer = _make_signer()
        expires = datetime.now(tz=UTC) + timedelta(minutes=15)
        token = signer.sign({"sub": "user"}, expires)

        # Tamper with the payload
        parts = token.split(".")
        parts[1] = parts[1] + "tampered"
        tampered = ".".join(parts)

        with pytest.raises(jwt.InvalidTokenError):
            signer.verify(tampered)
