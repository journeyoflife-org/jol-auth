# Incident Runbook

## Scope

This runbook covers incident response procedures for security events affecting the jol-auth service.

## Severity Levels

| Level | Description | Response Time | Example |
|---|---|---|---|
| P1 — Critical | Active data breach or token forgery | 15 minutes | Signing key compromise |
| P2 — High | Potential breach, contained | 1 hour | Suspected cross-tenant query |
| P3 — Medium | Policy violation, no data loss | 4 hours | Rate limit bypass |
| P4 — Low | Informational finding | Next business day | Dependency CVE (non-exploitable) |

## Response Procedure

### 1. Detection
- Alerts from monitoring (token anomaly, rate limit spike, audit gap)
- Reports via SECURITY.md disclosure process
- CodeQL / secret scanning findings

### 2. Containment
- **P1**: Immediately rotate signing keys (`scripts/rotate-jwks.py --emergency`)
- **P1**: Revoke all tokens for affected tenant(s)
- **P2**: Disable affected client or user accounts

### 3. Investigation
- Query audit events for the affected tenant
- Review distributed traces for the incident window
- Identify blast radius (tenants, users, tokens affected)

### 4. Remediation
- Apply fix or configuration change
- Rotate affected credentials
- Verify containment via integration tests

### 5. Communication
- Notify affected tenants per GDPR Art. 33/34 timeline (72 hours)
- Update internal incident tracker
- File post-incident review

### 6. Post-Incident
- Conduct blameless post-mortem within 5 business days
- Update threat model and runbook
- Implement preventive controls
