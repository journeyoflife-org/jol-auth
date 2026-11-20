"""Integration tests for the authorization code flow.

These tests exercise the PKCE and authorization code logic without
requiring a running PostgreSQL instance. Full end-to-end tests would
use a test database fixture.
"""

from datetime import UTC, datetime, timedelta

from app.core.security import generate_token, sha256_hex
from app.security.pkce import generate_code_challenge, generate_code_verifier, verify_code_challenge


class TestAuthorizationCodeFlow:
    def test_pkce_code_challenge_generation(self) -> None:
        """Verify S256 code challenge can be generated and verified."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method="S256")
        assert challenge != verifier
        assert verify_code_challenge(verifier, challenge, method="S256") is True

    def test_pkce_wrong_verifier_fails(self) -> None:
        """Verify PKCE rejects a mismatched verifier."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method="S256")
        wrong_verifier = generate_code_verifier()
        assert verify_code_challenge(wrong_verifier, challenge, method="S256") is False

    def test_authorization_code_hash_is_stable(self) -> None:
        """Verify authorization codes can be hashed deterministically."""
        code = generate_token(32)
        hash1 = sha256_hex(code)
        hash2 = sha256_hex(code)
        assert hash1 == hash2
        assert hash1 != code

    def test_different_codes_produce_different_hashes(self) -> None:
        """Verify different codes produce different hashes."""
        code1 = generate_token(32)
        code2 = generate_token(32)
        assert sha256_hex(code1) != sha256_hex(code2)

    def test_expired_code_detection(self) -> None:
        """Verify expired code timestamps can be detected."""
        from app.core.token_policy import TokenPolicy

        policy = TokenPolicy()
        expired = datetime.now(tz=UTC) - timedelta(minutes=10)
        valid = policy.authorization_code_expiry()
        assert expired < datetime.now(tz=UTC)
        assert valid > datetime.now(tz=UTC)
