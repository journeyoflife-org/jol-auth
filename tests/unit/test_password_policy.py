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
