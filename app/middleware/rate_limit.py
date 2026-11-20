"""Rate limiting middleware — applies Redis-backed rate limits per endpoint category.

Rate limit categories:
    - login:    /api/oauth/authorize, /api/users/login (5 req / 5 min per IP)
    - token:    /api/oauth/token                    (60 req / min per IP + client_id)
    - mfa:      /api/mfa/totp/verify                (10 req / 5 min per user)
    - api:      all other /api/* endpoints           (60 req / min per IP)

If Redis is unavailable, the middleware degrades gracefully (allows all
requests) and logs a warning — availability over strict enforcement.
"""

import logging
from typing import ClassVar

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.security.rate_limit import RateLimiter, RateLimitResult

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply sliding-window rate limits based on request path and method."""

    # Path prefix → (scope, limiter-factory)
    RATE_RULES: ClassVar[list[tuple[str, str, str]]] = [
        # (path_prefix, scope, limiter_type)
        ("/api/oauth/authorize", "login", "login"),
        ("/api/oauth/token", "token", "token"),
        ("/api/mfa/totp/verify", "mfa", "mfa"),
    ]

    DEFAULT_SCOPE = "api"
    DEFAULT_LIMITER = "api"

    EXEMPT_PATHS: ClassVar[frozenset[str]] = frozenset(
        {
            "/api/health",
            "/api/oidc/.well-known/openid-configuration",
            "/api/jwks/",
        }
    )

    def __init__(self, app, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app, **kwargs)
        self._limiters: dict[str, RateLimiter] = {}

    def _get_limiter(self, limiter_type: str) -> RateLimiter:
        """Get or create a rate limiter for the given type."""
        if limiter_type not in self._limiters:
            from app.security.rate_limit import (
                api_limiter,
                login_limiter,
                mfa_limiter,
                token_limiter,
            )

            factories = {
                "login": login_limiter,
                "token": token_limiter,
                "mfa": mfa_limiter,
                "api": api_limiter,
            }
            factory = factories.get(limiter_type, api_limiter)
            self._limiters[limiter_type] = factory()
        return self._limiters[limiter_type]

    def _match_rule(self, path: str) -> tuple[str, str]:
        """Match request path to a rate limit rule. Returns (scope, limiter_type)."""
        for prefix, scope, limiter_type in self.RATE_RULES:
            if path.startswith(prefix):
                return scope, limiter_type
        return self.DEFAULT_SCOPE, self.DEFAULT_LIMITER

    def _get_identifier(self, request: Request, scope: str) -> str:
        """Extract the rate-limit identifier from the request.

        - login/token: client IP address
        - mfa: authenticated user ID (from request state) or IP fallback
        - api: client IP address
        """
        if scope == "mfa":
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                return f"user:{user_id}"

        # Extract client IP (respecting X-Forwarded-For from trusted proxy)
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            # Take the first (original client) IP
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"

        return f"ip:{client_ip}"

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Skip non-API paths
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        scope, limiter_type = self._match_rule(request.url.path)
        identifier = self._get_identifier(request, scope)
        limiter = self._get_limiter(limiter_type)

        try:
            result: RateLimitResult = await limiter.check(scope, identifier)
        except Exception as exc:
            # Graceful degradation: if Redis is down, allow the request
            logger.warning("Rate limiter unavailable, allowing request: %s", exc)
            return await call_next(request)

        if not result.allowed:
            # Emit audit signal via request state for downstream logging
            request.state.rate_limited = True
            request.state.rate_limit_scope = scope
            request.state.rate_limit_identifier = identifier

            logger.warning(
                "Rate limit exceeded: scope=%s identifier=%s remaining=0 limit=%d",
                scope,
                identifier,
                result.limit,
            )

            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "scope": scope,
                    "retry_after": result.retry_after_seconds,
                },
                headers={
                    "Retry-After": str(result.retry_after_seconds),
                    "X-RateLimit-Limit": str(result.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(result.retry_after_seconds),
                },
            )

        # Add rate limit headers to successful responses
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(result.limit)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        return response
