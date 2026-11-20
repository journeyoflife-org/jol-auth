"""Password policy — strength validation and complexity requirements."""

import re


class PasswordPolicyError(ValueError):
    """Raised when a password does not meet policy requirements."""


def validate_password(password: str) -> None:
    """Validate a password against the JOL password policy.

    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        raise PasswordPolicyError("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        raise PasswordPolicyError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise PasswordPolicyError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        raise PasswordPolicyError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        raise PasswordPolicyError("Password must contain at least one special character.")
