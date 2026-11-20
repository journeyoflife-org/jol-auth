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

"""Tests for password policy — strength validation and edge cases."""

import pytest
from app.core.password_policy import PasswordPolicyError, validate_password


class TestPasswordPolicy:
    def test_valid_password_passes(self) -> None:
        validate_password("Str0ng!Pass#99")

    def test_too_short_raises(self) -> None:
        with pytest.raises(PasswordPolicyError, match="12 characters"):
            validate_password("Sh0rt!")

    def test_missing_uppercase_raises(self) -> None:
        with pytest.raises(PasswordPolicyError, match="uppercase"):
            validate_password("nouppercase123!")

    def test_missing_lowercase_raises(self) -> None:
        with pytest.raises(PasswordPolicyError, match="lowercase"):
            validate_password("NOLOWERCASE123!")

    def test_missing_digit_raises(self) -> None:
        with pytest.raises(PasswordPolicyError, match="digit"):
            validate_password("NoDigitsHere!!")

    def test_missing_special_char_raises(self) -> None:
        with pytest.raises(PasswordPolicyError, match="special"):
            validate_password("NoSpecial1234")

    def test_exactly_12_chars_passes(self) -> None:
        validate_password("Abc1!Abc1!Ab")

    def test_11_chars_fails(self) -> None:
        with pytest.raises(PasswordPolicyError):
            validate_password("Abc1!Abc1!A")

    def test_empty_password_fails(self) -> None:
        with pytest.raises(PasswordPolicyError):
            validate_password("")
