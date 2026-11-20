# ADR-002: Tenant Boundary Definition

## Status
Proposed

## Context
The platform serves 400,000+ institutions. Each institution must be strictly isolated from all others for GDPR compliance and data protection.

## Decision
- Each tenant is identified by a UUID (`tenant_id`)
- All data tables include a `tenant_id` column with a foreign key constraint
- The `TenantResolutionMiddleware` resolves the tenant from the `X-Tenant-ID` header
- All repository queries must include a `tenant_id` filter
- Cross-tenant access attempts raise `TenantIsolationError` and emit an audit event

## Consequences
- Every database query must be tenant-scoped — this is enforced via repository patterns
- Service-to-service calls must propagate the `tenant_id` header
- Testing must cover isolation at repository, service, and API levels
