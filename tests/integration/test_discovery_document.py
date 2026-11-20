"""Integration tests for the OIDC discovery document."""

from app.services.discovery_service import DiscoveryService


class TestDiscoveryDocument:
    def test_discovery_returns_valid_document(self) -> None:
        """Verify all required OIDC discovery fields are present."""
        svc = DiscoveryService()
        doc = svc.get_document()
        assert doc.issuer is not None
        assert doc.authorization_endpoint is not None
        assert doc.token_endpoint is not None
        assert doc.userinfo_endpoint is not None
        assert doc.jwks_uri is not None
        assert len(doc.scopes_supported) > 0
        assert len(doc.response_types_supported) > 0
        assert len(doc.grant_types_supported) > 0

    def test_jwks_uri_is_present(self) -> None:
        """Verify the JWKS URI is a valid URL path."""
        svc = DiscoveryService()
        doc = svc.get_document()
        assert "/api/jwks/" in doc.jwks_uri

    def test_supported_scopes_include_openid(self) -> None:
        """Verify 'openid' is in scopes_supported."""
        svc = DiscoveryService()
        doc = svc.get_document()
        assert "openid" in doc.scopes_supported

    def test_supported_grant_types(self) -> None:
        """Verify expected grant types are listed."""
        svc = DiscoveryService()
        doc = svc.get_document()
        assert "authorization_code" in doc.grant_types_supported
        assert "client_credentials" in doc.grant_types_supported
        assert "refresh_token" in doc.grant_types_supported

    def test_pkce_method_supported(self) -> None:
        """Verify S256 PKCE method is listed."""
        svc = DiscoveryService()
        doc = svc.get_document()
        assert "S256" in doc.code_challenge_methods_supported

    def test_signing_algorithm_is_rs256(self) -> None:
        """Verify RS256 is the signing algorithm."""
        svc = DiscoveryService()
        doc = svc.get_document()
        assert "RS256" in doc.id_token_signing_alg_values_supported
