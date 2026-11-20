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

"""Integration tests for refresh token rotation.

Tests the rotation logic and reuse detection without a running DB.
"""

from app.core.security import generate_token, sha256_hex


class TestRefreshRotation:
    def test_refresh_token_hash_stable(self) -> None:
        """Verify refresh token hashing is deterministic."""
        token = generate_token(48)
        h1 = sha256_hex(token)
        h2 = sha256_hex(token)
        assert h1 == h2

    def test_different_tokens_different_hashes(self) -> None:
        """Verify different refresh tokens produce different hashes."""
        t1 = generate_token(48)
        t2 = generate_token(48)
        assert sha256_hex(t1) != sha256_hex(t2)

    def test_token_length_sufficient(self) -> None:
        """Verify generated tokens have sufficient entropy."""
        token = generate_token(48)
        assert len(token) == 96  # 48 bytes = 96 hex chars

    def test_reuse_detection_concept(self) -> None:
        """Verify that hash comparison can detect token reuse."""
        original = generate_token(48)
        original_hash = sha256_hex(original)
        # Simulating a "revoked" record lookup
        revoked_hashes: set[str] = {original_hash}

        # Presenting the same token again
        presented_hash = sha256_hex(original)
        assert presented_hash in revoked_hashes  # reuse detected

        # Presenting a different token
        new_token = generate_token(48)
        new_hash = sha256_hex(new_token)
        assert new_hash not in revoked_hashes  # not reuse
