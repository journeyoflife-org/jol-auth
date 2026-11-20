# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for jol-auth."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_env: str = "development"
    app_debug: bool = False
    app_secret_key: str = ""
    app_host: str = "0.0.0.0"  # noqa: S104  — server bind address, not a secret
    app_port: int = 8000
    app_version: str = "0.1.0"

    # Database
    # credential-free default; real deployments source the DSN from .env/env (F-30)
    database_url: str = "postgresql+asyncpg://localhost:5432/jol_auth"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT / OIDC
    jwt_issuer: str = "https://auth.journeyoflife.org"
    jwt_audience: str = "https://api.journeyoflife.org"
    jwt_signing_algorithm: str = "RS256"
    jwks_kid: str = ""
    jwks_private_key_path: str = ""
    jwks_public_key_path: str = ""

    # OAuth 2.0
    oauth_authorization_code_ttl: int = 300
    oauth_access_token_ttl: int = 900
    oauth_refresh_token_ttl: int = 2592000
    oauth_refresh_rotation: bool = True

    # Session
    session_idle_timeout: int = 1800
    session_absolute_timeout: int = 86400
    session_cookie_name: str = "jol_session"
    session_cookie_secure: bool = True
    session_cookie_samesite: str = "lax"

    # MFA
    mfa_totp_issuer: str = "JourneyOfLife"
    mfa_totp_digits: int = 6
    mfa_totp_period: int = 30
    mfa_encryption_key: str = ""  # Fernet key for TOTP secret encryption (base64-urlsafe)

    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_login_attempts: int = 5
    rate_limit_token_per_minute: int = 30
    rate_limit_mfa_attempts: int = 10

    # Telemetry
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "jol-auth"
    log_level: str = "INFO"

    # CORS
    cors_origins: str = "http://localhost:3000"


settings = Settings()
