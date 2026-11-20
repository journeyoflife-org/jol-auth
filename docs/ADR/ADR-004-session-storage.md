# ADR-004: Session Storage Strategy

## Status
Proposed

## Context
Sessions must support idle timeout, absolute timeout, and per-tenant configuration. The platform requires GDPR-compliant consent tracking.

## Decision
- Sessions are stored in PostgreSQL (authoritative) with Redis as a cache layer
- Each session has `idle_timeout` (default 30 min) and `absolute_timeout` (default 24 hours)
- Sessions include `ip_address` and `user_agent` for anomaly detection
- Session revocation is immediate (cache invalidation + DB flag)
- Consent metadata is tracked per session for GDPR compliance

## Consequences
- Redis is a performance optimisation — PostgreSQL is the source of truth
- Session validation must check both idle and absolute timeouts
- Revocation must invalidate both the cache and the database record
