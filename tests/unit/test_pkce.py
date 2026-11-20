"""Tests for PKCE — code challenge generation and verification."""

from app.security.pkce import generate_code_challenge, generate_code_verifier, verify_code_challenge


class TestPKCE:
    def test_code_verifier_length(self) -> None:
        verifier = generate_code_verifier()
        assert 43 <= len(verifier) <= 128

    def test_s256_challenge_differs_from_verifier(self) -> None:
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method="S256")
        assert challenge != verifier

    def test_plain_challenge_equals_verifier(self) -> None:
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method="plain")
        assert challenge == verifier

    def test_s256_verification_round_trip(self) -> None:
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method="S256")
        assert verify_code_challenge(verifier, challenge, method="S256") is True

    def test_s256_verification_fails_with_wrong_verifier(self) -> None:
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method="S256")
        wrong_verifier = generate_code_verifier()
        assert verify_code_challenge(wrong_verifier, challenge, method="S256") is False

    def test_unsupported_method_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="Unsupported"):
            generate_code_challenge("verifier", method="invalid")
