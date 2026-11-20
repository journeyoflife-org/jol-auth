"""OIDC claims — standard claim extraction and mapping per OpenID Connect Core 1.0.

Standard claim sets:
    - ``profile`` scope: sub, name, preferred_username, given_name,
      family_name, middle_name, nickname, profile, picture, website,
      gender, birthdate, zoneinfo, locale, updated_at
    - ``email`` scope: email, email_verified
    - ``address`` scope: address (JSON object)
    - ``phone`` scope: phone_number, phone_number_verified

ID token standard claims:
    - iss, sub, aud, exp, iat (registered)
    - nonce (when provided in auth request)
    - acr (Authentication Context Class Reference)
    - amr (Authentication Methods References)
    - auth_time (when the user authenticated)
    - at_hash (access token hash for binding)
    - c_hash (code hash for binding)
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass
class OIDCClaims:
    """Standard OpenID Connect claims."""

    sub: str
    iss: str
    aud: str
    exp: int
    iat: int
    nonce: str | None = None
    email: str | None = None
    name: str | None = None
    preferred_username: str | None = None


# Scopes → claims mapping per OIDC Core 1.0 §5.4
SCOPE_CLAIMS_MAP: dict[str, list[str]] = {
    "openid": [],
    "profile": [
        "name",
        "preferred_username",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
    ],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
}


def build_id_token_claims(
    user: dict[str, Any],
    issuer: str,
    audience: str,
    nonce: str | None = None,
    auth_time: int | None = None,
    acr: str | None = None,
    amr: list[str] | None = None,
    access_token: str | None = None,
    code: str | None = None,
) -> dict[str, Any]:
    """Build the claim set for an OIDC ID token.

    Per OpenID Connect Core 1.0 §2, the ID token MUST contain:
    ``iss``, ``sub``, ``aud``, ``exp``, ``iat``.

    Optional but recommended:
    - ``nonce``: Required if the auth request contained a nonce
    - ``auth_time``: Time the user authenticated (required if ``max_age`` was sent)
    - ``acr``: Authentication Context Class Reference
    - ``amr``: Authentication Methods References (e.g. ``["pwd", "otp"]``)
    - ``at_hash``: Access token hash (required when ``response_type=code``)
    - ``c_hash``: Code hash (required when ``response_type=code id_token``)

    Args:
        user: User record dict with fields: id, email, display_name, etc.
        issuer: Issuer URL (``iss`` claim).
        audience: Intended audience (``aud`` claim) — typically the client_id.
        nonce: Nonce from the authorization request.
        auth_time: Unix timestamp of user authentication.
        acr: Authentication Context Class Reference (e.g. ``"urn:mace:incommon:iap:silver"``).
        amr: List of authentication methods used.
        access_token: Access token for at_hash computation.
        code: Authorization code for c_hash computation.

    Returns:
        Dict of claims suitable for JWT encoding.
    """
    now = datetime.now(tz=UTC)
    claims: dict[str, Any] = {
        "sub": str(user["id"]),
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + 900,  # 15 min — ID tokens are short-lived
    }

    if nonce:
        claims["nonce"] = nonce

    if auth_time is not None:
        claims["auth_time"] = auth_time

    if acr:
        claims["acr"] = acr

    if amr:
        claims["amr"] = amr

    # at_hash: base64url-encoded leftmost half of SHA-256(access_token)
    if access_token:
        import hashlib

        digest = hashlib.sha256(access_token.encode()).digest()
        at_hash = digest[: len(digest) // 2]
        import base64

        claims["at_hash"] = base64.urlsafe_b64encode(at_hash).rstrip(b"=").decode()

    # c_hash: same algorithm but over the authorization code
    if code:
        import base64
        import hashlib

        digest = hashlib.sha256(code.encode()).digest()
        c_hash = digest[: len(digest) // 2]
        claims["c_hash"] = base64.urlsafe_b64encode(c_hash).rstrip(b"=").decode()

    return claims


def build_userinfo_claims(user: dict[str, Any], requested_scopes: list[str] | None = None) -> dict[str, Any]:
    """Extract userinfo claims based on requested scopes.

    Only claims corresponding to the granted scopes are returned.
    The ``sub`` claim is always included per OIDC Core §5.1.
    """
    claims: dict[str, Any] = {
        "sub": str(user["id"]),
    }

    scopes = requested_scopes or ["openid", "profile", "email"]

    if "profile" in scopes:
        if user.get("display_name"):
            claims["name"] = user["display_name"]
        if user.get("email"):
            claims["preferred_username"] = user["email"]
        # These would come from extended user profile data
        if user.get("given_name"):
            claims["given_name"] = user["given_name"]
        if user.get("family_name"):
            claims["family_name"] = user["family_name"]
        if user.get("locale"):
            claims["locale"] = user["locale"]
        if user.get("updated_at"):
            claims["updated_at"] = user["updated_at"]

    if "email" in scopes:
        if user.get("email"):
            claims["email"] = user["email"]
        claims["email_verified"] = user.get("email_verified", False)

    return claims


def get_claims_for_scopes(scopes: list[str]) -> list[str]:
    """Return the list of claim names that should be available for the given scopes."""
    result: list[str] = ["sub"]
    for scope in scopes:
        result.extend(SCOPE_CLAIMS_MAP.get(scope, []))
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for claim in result:
        if claim not in seen:
            seen.add(claim)
            unique.append(claim)
    return unique
