"""Audit context middleware — enriches audit events with request metadata."""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class AuditContextMiddleware(BaseHTTPMiddleware):
    """Capture request metadata (IP, User-Agent) for audit event enrichment."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.audit_ip = request.client.host if request.client else None
        request.state.audit_user_agent = request.headers.get("User-Agent")
        response = await call_next(request)
        return response
