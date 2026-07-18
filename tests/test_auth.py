"""Smoke tests for the jol-auth package."""

import jol_auth


def test_package_version() -> None:
    """Verify the package exposes a version string."""
    assert isinstance(jol_auth.__version__, str)
    assert jol_auth.__version__ == "0.1.0"


def test_package_docstring() -> None:
    """Verify the package docstring references core auth concepts."""
    assert jol_auth.__doc__ is not None
    doc = jol_auth.__doc__
    assert "OAuth" in doc
    assert "RBAC" in doc
    assert "Journey Of Life" in doc
