# ADR-001: Issuer and Discovery Configuration

## Status
Proposed

## Context
The OIDC discovery document must be served at a well-known URL. The issuer URL is used as the `iss` claim in all tokens and must be consistent across environments.

## Decision
- The issuer URL is configured via the `JWT_ISSUER` environment variable
- The discovery document is served at `{issuer}/.well-known/openid-configuration`
- Each environment (dev, staging, production) has a distinct issuer URL
- The issuer URL never includes a trailing slash

## Consequences
- Token verification across services requires consistent issuer configuration
- Environment promotion requires configuration change, not code change
