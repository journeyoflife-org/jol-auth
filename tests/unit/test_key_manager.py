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

"""Tests for key manager — generation, rotation, and key lookup."""

import pytest
from app.security.key_manager import KeyManager


class TestKeyManager:
    def test_generate_key_pair_returns_kid(self) -> None:
        km = KeyManager()
        kid = km.generate_key_pair()
        assert isinstance(kid, str)
        assert len(kid) > 0

    def test_no_key_raises_on_access(self) -> None:
        km = KeyManager()
        with pytest.raises(RuntimeError, match="No signing key"):
            km.get_private_key()
        with pytest.raises(RuntimeError, match="No signing key"):
            km.get_public_key()
        with pytest.raises(RuntimeError, match="No signing key"):
            _ = km.kid

    def test_current_key_accessible_after_generation(self) -> None:
        km = KeyManager()
        kid = km.generate_key_pair()
        assert km.kid == kid
        assert km.get_private_key() is not None
        assert km.get_public_key() is not None

    def test_rotation_changes_kid(self) -> None:
        km = KeyManager()
        kid1 = km.generate_key_pair()
        kid2 = km.rotate()
        assert kid1 != kid2
        assert km.kid == kid2

    def test_previous_key_still_accessible_after_rotation(self) -> None:
        km = KeyManager()
        kid1 = km.generate_key_pair()
        kid2 = km.rotate()

        pair1 = km.get_key_by_kid(kid1)
        pair2 = km.get_key_by_kid(kid2)
        assert pair1 is not None
        assert pair2 is not None
        assert pair1.kid == kid1
        assert pair2.kid == kid2

    def test_get_key_by_unknown_kid_returns_none(self) -> None:
        km = KeyManager()
        km.generate_key_pair()
        assert km.get_key_by_kid("nonexistent") is None

    def test_all_keys_returns_current_and_previous(self) -> None:
        km = KeyManager()
        km.generate_key_pair()
        assert len(km.all_keys()) == 1

        km.rotate()
        assert len(km.all_keys()) == 2

    def test_double_rotation_drops_oldest_key(self) -> None:
        km = KeyManager()
        kid1 = km.generate_key_pair()
        km.rotate()
        km.rotate()

        # Only the last two keys should be available
        assert km.get_key_by_kid(kid1) is None
        assert len(km.all_keys()) == 2

    def test_generate_with_custom_key_size(self) -> None:
        km = KeyManager()
        km.generate_key_pair(key_size=4096)
        assert km.get_private_key().key_size == 4096
