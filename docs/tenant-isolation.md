# Tenant Isolation

## Overview

Tenant isolation is the foundational security boundary in jol-auth. Each institution's data, tokens, sessions, and audit events are strictly segregated.

## Isolation Layers

### 1. Middleware Layer
- `TenantResolutionMiddleware` resolves the tenant from `X-Tenant-ID` header
- Requests without a valid tenant context are rejected with 400

### 2. Database Layer
- All tables include a `tenant_id` foreign key
- Repository methods always filter by `tenant_id`
- No raw SQL queries are permitted — all access goes through typed repositories

### 3. Service Layer
- All service methods accept `tenant_id` as an explicit parameter
- `TenantIsolationError` is raised on cross-tenant access attempts

### 4. Token Layer
- Access tokens include `tenant_id` in the `tid` claim
- Token validation verifies the `tid` claim matches the requesting tenant

## Testing

- `tests/unit/test_tenant_isolation.py` — unit-level tenant scoping
- `tests/security/test_no_cross_tenant_queries.py` — integration-level isolation
- CI enforces that no query can execute without a `tenant_id` filter

## Failure Modes

| Scenario | Behaviour |
|---|---|
| Missing X-Tenant-ID header | 400 Bad Request |
| Invalid tenant ID | 403 Forbidden |
| Token from different tenant | 403 Forbidden |
| Cross-tenant query attempt | TenantIsolationError raised, audit event emitted |
