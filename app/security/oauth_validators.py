"""OAuth validators — parameter and grant validation helpers."""

from app.core.exceptions import AuthError


def validate_redirect_uri(uri: str, allowed_uris: list[str]) -> None:
    """Ensure the redirect URI matches a registered URI."""
    if uri not in allowed_uris:
        raise AuthError(status_code=400, detail="Invalid redirect_uri.")


def validate_scope(requested: str, allowed: str) -> list[str]:
    """Return the intersection of requested and allowed scopes."""
    requested_set = set(requested.split())
    allowed_set = set(allowed.split())
    valid = requested_set & allowed_set
    if not valid:
        raise AuthError(status_code=400, detail="No valid scopes requested.")
    return sorted(valid)


def validate_grant_type(grant_type: str, allowed_types: list[str]) -> None:
    """Ensure the grant type is permitted for the client."""
    if grant_type not in allowed_types:
        raise AuthError(status_code=400, detail=f"Unsupported grant_type: {grant_type}")
