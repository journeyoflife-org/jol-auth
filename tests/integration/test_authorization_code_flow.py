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
