"""Domain-specific exception hierarchy for jol-auth."""

from fastapi import HTTPException, status


class AuthError(HTTPException):
    """Base class for authentication/authorization HTTP errors."""


class UnauthorizedError(AuthError):
    """401 — credentials missing or invalid."""

    def __init__(self, detail: str = "Authentication required.") -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class ForbiddenError(AuthError):
    """403 — insufficient permissions."""

    def __init__(self, detail: str = "Insufficient permissions.") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class NotFoundError(AuthError):
    """404 — resource does not exist."""

    def __init__(self, detail: str = "Resource not found.") -> None:
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class ConflictError(AuthError):
    """409 — resource already exists."""

    def __init__(self, detail: str = "Resource already exists.") -> None:
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)


class TenantIsolationError(AuthError):
    """403 — cross-tenant access attempt."""

    def __init__(self, detail: str = "Cross-tenant access denied.") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class MFARequiredError(AuthError):
    """403 — MFA challenge required before proceeding."""

    def __init__(self, detail: str = "Multi-factor authentication required.") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class RateLimitError(AuthError):
    """429 — rate limit exceeded."""

    def __init__(self, detail: str = "Rate limit exceeded.") -> None:
        super().__init__(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)
