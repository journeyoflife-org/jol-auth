# Threat Model

## Overview

This document captures the threat model for jol-auth, aligned with the STRIDE methodology and the JOL platform's compliance requirements (GDPR, ISO 27001, SOC 2).

## Assets

| Asset | Classification | Impact if Compromised |
|---|---|---|
| Signing private keys | Critical | Token forgery, full platform compromise |
| User credentials | High | Account takeover, data breach |
| Refresh tokens | High | Persistent session hijacking |
| Audit logs | High | Compliance failure, forensic gaps |
| Tenant data | High (GDPR Art. 9) | Regulatory fines, data breach |

## Threat Categories (STRIDE)

### Spoofing
- Forged tokens via compromised signing key
- OAuth client impersonation

### Tampering
- PKCE bypass by modifying code challenge
- Audit log tampering

### Repudiation
- Denial of token issuance or revocation

### Information Disclosure
- Cross-tenant data leakage via missing tenant_id filters
- Token scope leakage exposing privileges

### Denial of Service
- Token endpoint flooding
- Brute-force credential stuffing

### Elevation of Privilege
- Scope escalation via token manipulation
- RBAC bypass via missing permission checks

## Mitigations

| Threat | Mitigation |
|---|---|
| Key compromise | Hardware-backed key storage, rotation schedule, HSM in production |
| Cross-tenant leakage | Mandatory tenant_id filter on all queries, TenantResolutionMiddleware |
| Token forgery | RS256 signing, JWKS verification, short-lived tokens |
| Brute force | Rate limiting, account lockout policy |
| Audit tampering | Append-only storage, integrity checksums |

## Residual Risks

- Insider threat with vault access (mitigated by MFA + audit)
- Zero-day in dependency (mitigated by CodeQL + weekly scans)
