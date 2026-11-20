"""Smoke tests — verify the conftest infrastructure and auth dependencies work.

These tests exercise the real FastAPI app via httpx ASGI transport against
an in-memory SQLite database.  They are the first tests in the repo that
actually hit HTTP endpoints.

If these pass, the test infrastructure (conftest.py) is functional and the
auth dependencies (get_current_user, require_permission) are correctly
wired into the routers.
"""

from httpx import AsyncClient


class TestHealthEndpoint:
    """Health endpoint requires no authentication."""

    async def test_health_returns_200(self, client: AsyncClient) -> None:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestAuthenticationEnforcement:
    """Every protected endpoint must reject unauthenticated requests."""

    async def test_users_list_without_auth_returns_401(
        self, client: AsyncClient, no_auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/users/", headers=no_auth_headers)
        assert resp.status_code == 401

    async def test_mfa_factors_without_auth_returns_401(
        self, client: AsyncClient, no_auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/mfa/factors", headers=no_auth_headers)
        assert resp.status_code == 401

    async def test_sessions_without_auth_returns_401(
        self, client: AsyncClient, no_auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/sessions/", headers=no_auth_headers)
        assert resp.status_code == 401

    async def test_admin_audit_events_without_auth_returns_401(
        self, client: AsyncClient, no_auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/admin/audit-events", headers=no_auth_headers)
        assert resp.status_code == 401

    async def test_no_tenant_header_returns_400(self, client: AsyncClient) -> None:
        """Requests without X-Tenant-ID are rejected by the middleware."""
        resp = await client.get("/api/users/")
        assert resp.status_code == 400

    async def test_unknown_tenant_returns_403(
        self, client: AsyncClient, unknown_tenant_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/users/", headers=unknown_tenant_headers)
        assert resp.status_code == 403


class TestValidAuthentication:
    """Authenticated requests with valid tokens succeed."""

    async def test_users_list_with_valid_auth_returns_200(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/users/", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        assert len(body) >= 1

    async def test_mfa_factors_with_valid_auth_returns_200(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/mfa/factors", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_sessions_with_valid_auth_returns_200(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/api/sessions/", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestTokenRejection:
    """Invalid, expired, and tampered tokens are rejected."""

    async def test_expired_token_returns_401(self, client: AsyncClient, expired_headers: dict[str, str]) -> None:
        resp = await client.get("/api/users/", headers=expired_headers)
        assert resp.status_code == 401

    async def test_tampered_token_returns_401(self, client: AsyncClient, tampered_headers: dict[str, str]) -> None:
        resp = await client.get("/api/users/", headers=tampered_headers)
        assert resp.status_code == 401

    async def test_inactive_user_token_returns_401(self, client: AsyncClient, inactive_headers: dict[str, str]) -> None:
        resp = await client.get("/api/users/", headers=inactive_headers)
        assert resp.status_code == 401

    async def test_wrong_tenant_token_returns_401(
        self, client: AsyncClient, wrong_tenant_headers: dict[str, str]
    ) -> None:
        """Token tid claim must match the X-Tenant-ID header."""
        resp = await client.get("/api/users/", headers=wrong_tenant_headers)
        assert resp.status_code == 401


class TestRBACEnforcement:
    """Admin endpoints require admin-level permissions."""

    async def test_admin_audit_events_with_regular_user_returns_403(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        """Regular user (no roles) gets 403 on admin endpoints."""
        resp = await client.get("/api/admin/audit-events", headers=auth_headers)
        assert resp.status_code == 403

    async def test_admin_audit_events_with_admin_returns_200(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        admin_role,  # noqa: ANN001 — fixture ensures role exists in DB
    ) -> None:
        """Admin user with 'admin' role gets 200."""
        resp = await client.get("/api/admin/audit-events", headers=admin_headers)
        assert resp.status_code == 200

    async def test_admin_register_client_with_regular_user_returns_403(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        resp = await client.post(
            "/api/admin/clients",
            headers=auth_headers,
            json={
                "name": "test-client",
                "redirect_uris": ["http://localhost:3000/callback"],
                "grant_types": ["authorization_code"],
                "scopes": ["openid"],
            },
        )
        assert resp.status_code == 403
