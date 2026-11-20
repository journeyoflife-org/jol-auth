"""Request ID middleware — assigns a unique ID to every request for tracing."""

import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class RequestIDMiddleware(BaseHTTPMiddleware):
    HEADER_NAME = "X-Request-ID"

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get(self.HEADER_NAME, str(uuid.uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[self.HEADER_NAME] = request_id
        return response
