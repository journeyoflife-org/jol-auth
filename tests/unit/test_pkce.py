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
