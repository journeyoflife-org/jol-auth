# JOL Platform — Production Readiness Review

**Classification:** Confidential — Internal Use Only
**Date:** 2026-07-18
**Reviewers:** Principal Software Architect, Principal Security Engineer, PostgreSQL Architect, IAM Architect, DevSecOps Engineer, GDPR Compliance Officer, SOC 2 Lead Auditor, ISO 27001 Lead Implementer
**Scope:** jol-auth identity service + JOL PostgreSQL cluster (6 databases)
**Compliance Targets:** GDPR, SOC 2 Type II, ISO 27001, OWASP ASVS Level 2+, Zero Trust Architecture

---

## Table of Contents

1. [Security Architecture Review](#1-security-architecture-review)
2. [PostgreSQL Hardening Plan](#2-postgresql-hardening-plan)
3. [Identity & Access Management Design](#3-identity--access-management-design)
4. [Audit Architecture](#4-audit-architecture)
5. [GDPR Architecture](#5-gdpr-architecture)
6. [Multi-Tenant SaaS Architecture](#6-multi-tenant-saas-architecture)
7. [Infrastructure Architecture](#7-infrastructure-architecture)
8. [AI Platform Architecture](#8-ai-platform-architecture)
9. [Deliverables](#9-deliverables)

---

## 1. Security Architecture Review

### 1.1 Threat Model (STRIDE)

| Threat Category | Specific Threat | Current Mitigation | Gap Severity |
|---|---|---|---|
| **Spoofing** | Forged JWT via compromised signing key | RS256 signing, key rotation, JWKS verification | **CRITICAL** — Keys generated in-memory, no HSM, 2048-bit RSA |
| **Spoofing** | OAuth client impersonation | Client secret hashing (Argon2id), tenant binding | MEDIUM — No mTLS for service-to-service auth |
| **Spoofing** | Tenant header spoofing (X-Tenant-ID) | UUID validation, DB lookup, active status check | LOW — Properly implemented |
| **Tampering** | PKCE bypass | S256 challenge method enforced | LOW — Properly implemented |
| **Tampering** | Audit log tampering | Append-only application logic | **CRITICAL** — No DB-level immutability constraints; UPDATE/DELETE not blocked |
| **Tampering** | Token claim manipulation | RS256 signature verification, iss/aud/exp validation | LOW — Properly implemented |
| **Repudiation** | Denial of token issuance | Audit events for token.issued, token.refreshed | MEDIUM — Request ID not included in audit events |
| **Repudiation** | Denial of admin actions | Audit events for admin.action | MEDIUM — No cryptographic chain (hash chaining) for audit integrity |
| **Information Disclosure** | Cross-tenant data leakage | tenant_id filters on all repositories, token tid claim | **HIGH** — No database-level RLS; relies entirely on application layer |
| **Information Disclosure** | TOTP secret exposure | Hashed with Argon2id | **CRITICAL** — Hashing breaks verification; implementation is broken |
| **Information Disclosure** | Error message information leakage | Generic error messages in most paths | LOW — Some paths leak detail (e.g., "Client mismatch") |
| **Denial of Service** | Token endpoint flooding | None | **CRITICAL** — Rate limiter is a stub (NotImplementedError) |
| **Denial of Service** | Credential stuffing | None | **CRITICAL** — No account lockout, no rate limiting, no CAPTCHA |
| **Denial of Service** | Session table growth | Idle/absolute timeout checks at access time | MEDIUM — No background cleanup job; table grows unbounded |
| **Elevation of Privilege** | Scope escalation | Scope intersection (requested ∩ allowed) | LOW — Properly implemented |
| **Elevation of Privilege** | RBAC bypass | require_permission dependency on admin endpoints | MEDIUM — Permission strings stored as comma-separated text, not normalized |
| **Elevation of Privilege** | Missing auth on endpoints | All endpoints except health/discovery/jwks require tenant+auth | LOW — Properly implemented |

### 1.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERNET (Zero Trust)                         │
│                         Hostile actors assumed                       │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ TLS 1.3 (NGINX terminates)
┌──────────────────────────────▼──────────────────────────────────────┐
│                     TRUST BOUNDARY 1: Edge / WAF                     │
│  NGINX reverse proxy + WAF + DDoS protection + rate limiting        │
│  [GAP: Not deployed — dev runs uvicorn directly on 0.0.0.0:8000]   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                  TRUST BOUNDARY 2: Application Layer                 │
│  FastAPI + middleware stack (RequestID → SecurityHeaders →           │
│  TenantResolution → AuditContext)                                   │
│  [GAP: No CORS validation against tenant, no CSRF tokens]          │
└──────────┬───────────────────────────────┬──────────────────────────┘
           │                               │
┌──────────▼──────────┐        ┌──────────▼──────────────────────────┐
│  TRUST BOUNDARY 3:  │        │     TRUST BOUNDARY 3b: Redis         │
│  PostgreSQL Cluster │        │  [GAP: No AUTH configured, no TLS]  │
│  scram-sha-256 auth │        └─────────────────────────────────────┘
│  [GAP: No RLS,      │
│   no TDE, no audit  │
│   trigger]          │
└─────────────────────┘
```

### 1.3 Attack Surfaces

| Surface | Exposure | Current Protection | Risk |
|---|---|---|---|
| `/api/oauth/token` | Public | PKCE, client secret | **CRITICAL** — No rate limiting |
| `/api/oauth/authorize` | Authenticated | Session check, client validation | HIGH — No CSRF token |
| `/api/users/` | Authenticated | Bearer token, tenant scope | MEDIUM — No input sanitization beyond Pydantic |
| `/api/admin/clients` | RBAC (clients:write) | require_permission | MEDIUM — No MFA enforcement on admin |
| `/api/mfa/totp/enroll` | Authenticated | Bearer token | MEDIUM — TOTP enrollment broken |
| `/api/oidc/userinfo` | Bearer token | Token validation, tenant binding | LOW |
| `/api/jwks/` | Public | None needed | LOW |
| `/api/health` | Public | None needed | LOW — Exposes no sensitive data |
| Database (5432) | localhost only | scram-sha-256 | MEDIUM — No TLS on connection |

### 1.4 Privilege Escalation Paths

**Path 1: Application Bug → Cross-Tenant Access**
```
Attacker → Compromised tenant A token → Bug in repository omitting tenant_id filter
→ Access to tenant B data
```
**Current defense:** Application-layer tenant_id filters
**Gap:** No database-level RLS as defense-in-depth. A single missing filter = full cross-tenant breach.

**Path 2: RBAC Permission String Injection**
```
Attacker → Compromised admin token → Create role with wildcard permissions
→ Escalate to platform-level access
```
**Current defense:** Permission strings parsed as "resource:action"
**Gap:** No permission allowlist; arbitrary resource/action strings accepted.

**Path 3: Key Compromise → Token Forgery**
```
Attacker → Extract in-memory RSA private key → Sign arbitrary JWTs
→ Full platform impersonation
```
**Current defense:** Key rotation (90-day schedule documented but not automated)
**Gap:** Keys stored in process memory, no HSM, no PKCS#11, 2048-bit (NIST recommends 3072+ by 2030).

### 1.5 Data Flow Diagram

```
User Browser ──HTTPS──▶ NGINX ──HTTP──▶ FastAPI (uvicorn)
                                              │
                    ┌─────────────────────────┼─────────────────────┐
                    │                         │                       │
                    ▼                         ▼                       ▼
            PostgreSQL              Redis (sessions,           JWKS (in-memory
            (jol_identity)           rate limit - STUB)        RSA key pair)
                    │
                    ▼
            Tables: tenants, users, sessions, tokens,
                    refresh_tokens, clients, mfa_factors,
                    authorization_codes, audit_events, roles
```

**Gap:** Audit events are stored in `jol_identity` database, not the dedicated `jol_audit` database.

### 1.6 Authentication Flows

**Authorization Code with PKCE** — Implemented
- `POST /api/oauth/authorize` → generates code with code_challenge
- `POST /api/oauth/token` (grant_type=authorization_code) → verifies PKCE, issues tokens
- **Gap:** No user login UI; `request.state.user_id` is never set by any middleware

**Client Credentials** — Implemented
- `POST /api/oauth/token` (grant_type=client_credentials) → validates secret, issues tokens

**Refresh Token Rotation** — Implemented
- `POST /api/oauth/token` (grant_type=refresh_token) → rotates token, detects reuse
- Family-wide revocation on reuse detection

**Token Revocation (RFC 7009)** — Implemented
- `POST /api/oauth/revoke` → always returns 200

**Token Introspection (RFC 7662)** — Implemented
- `POST /api/oauth/introspect` → returns active/inactive

### 1.7 Authorization Model

**RBAC Implementation:**
- Users have a `roles` column (comma-separated role names)
- Roles have a `permissions` column (comma-separated "resource:action" strings)
- `require_permission(resource, action)` dependency checks user roles against tenant roles

**Gaps:**
- No ABAC (Attribute-Based Access Control) for fine-grained access
- No role hierarchy (admin > manager > user)
- Permission strings not validated against an allowlist
- No denial-of-permission mechanism (only allow rules)
- No attribute-based policies (e.g., time-based, IP-based access)

---

## 2. PostgreSQL Hardening Plan

### 2.1 Roles and Permissions — Current State vs. Target

| Database | Current Owner | Has CREATEDB? | Has CREATEROLE? | Target |
|---|---|---|---|---|
| jol_platform_control | jol_control_user | Unknown | Unknown | NO |
| jol_identity | jol_identity_user | NO | NO | NO |
| jol_audit | jol_audit_user | NO | NO | NO + INSERT-only |
| jol_ai_platform | jol_ai_user | NO | NO | NO |
| jol_media_storage | jol_media_user | NO | NO | NO |
| jol_lt_platform_prod | jol_lt_app_user | NO | NO | NO |

**Required actions:**

```sql
-- Revoke excessive privileges
REVOKE CREATEDB, CREATEROLE, SUPERUSER FROM jol_identity_user;
REVOKE CREATEDB, CREATEROLE, SUPERUSER FROM jol_audit_user;
REVOKE CREATEDB, CREATEROLE, SUPERUSER FROM jol_ai_user;
REVOKE CREATEDB, CREATEROLE, SUPERUSER FROM jol_media_user;
REVOKE CREATEDB, CREATEROLE, SUPERUSER FROM jol_lt_app_user;
REVOKE CREATEDB, CREATEROLE, SUPERUSER FROM jol_control_user;

-- jol_audit_user should be INSERT-only (append-only)
REVOKE UPDATE, DELETE ON audit_events FROM jol_audit_user;
GRANT INSERT ON audit_events TO jol_audit_user;
GRANT SELECT ON audit_events TO jol_audit_user; -- for querying

-- Create a separate read-only role for reporting
CREATE ROLE jol_audit_reader WITH LOGIN PASSWORD '<strong-password>';
GRANT SELECT ON audit_events TO jol_audit_reader;
```

### 2.2 Least Privilege Model

```
Application Roles:
├── jol_identity_app     — INSERT, UPDATE, SELECT on all tables (no DELETE)
├── jol_identity_reader  — SELECT only (for reporting/dashboards)
├── jol_audit_writer     — INSERT only on audit_events (no UPDATE/DELETE)
├── jol_audit_reader     — SELECT only on audit_events
├── jol_lt_app          — Full CRUD on business tables (with RLS)
├── jol_lt_reader       — SELECT only on business tables (with RLS)
└── jol_control_admin   — Full CRUD on control plane tables

Migration Roles:
├── jol_migrator        — DDL privileges (used only during migrations)
└── (revoked after migration)
```

### 2.3 Row Level Security Design

**CRITICAL GAP:** No RLS policies exist. Tenant isolation relies entirely on application-layer `tenant_id` filters. This is insufficient for SOC 2/ISO 27001 compliance.

**Required RLS implementation:**

```sql
-- Enable RLS on all tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- Create tenant isolation policies
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON tokens
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON refresh_tokens
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON clients
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON mfa_factors
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON authorization_codes
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON roles
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation ON audit_events
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Application must set tenant_id before each query:
-- SET LOCAL app.tenant_id = '<uuid>';
```

**Application change required:** Every database session must execute `SET LOCAL app.tenant_id = '<uuid>'` before any query. This can be done in the `get_db` dependency:

```python
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        # Set tenant context for RLS
        await session.execute(text("SET LOCAL app.tenant_id = :tid"), {"tid": str(tenant_id)})
        yield session
```

### 2.4 Backup Architecture

**Current state:** No backup automation. Manual `pg_dump` only.

**Required architecture:**

```
Backup Strategy:
├── Full backup: pg_basebackup weekly (Sunday 02:00 UTC)
├── WAL archiving: Continuous (archive_command → MinIO/S3)
├── Incremental: pgBackRest differential daily
├── Retention:
│   ├── Daily: 30 days
│   ├── Weekly: 12 weeks
│   ├── Monthly: 12 months
│   └── Yearly: 7 years (GDPR compliance)
├── Encryption: AES-256 at rest (pgBackRest built-in)
├── Compression: zstd (pgBackRest)
├── Off-site: Replicate to secondary region
└── Testing: Monthly restore test to staging

Per-database backup:
├── jol_platform_control — Weekly full + WAL
├── jol_identity — Daily full + WAL (frequent token churn)
├── jol_audit — Weekly full + WAL (append-only, low churn)
├── jol_ai_platform — Weekly full + WAL
├── jol_media_storage — Weekly full (metadata only; files in MinIO)
└── jol_lt_platform_prod — Daily full + WAL (business-critical)
```

### 2.5 PITR (Point-in-Time Recovery)

```ini
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'pgBackRest --stanza=jol archive-push %p'
max_wal_senders = 3
hot_standby = on

# Recovery target: Any point within 30 days
# RPO: < 5 minutes (WAL streaming)
# RTO: < 2 hours (restore + replay)
```

### 2.6 Encryption at Rest

| Layer | Current | Required | Priority |
|---|---|---|---|
| Database files | None | LUKS dm-crypt (AES-256) or cloud-managed encryption | **HIGH** |
| WAL files | None | Encrypted via pgBackRest | **HIGH** |
| Backups | None | AES-256 (pgBackRest built-in) | **CRITICAL** |
| TOTP secrets | Argon2id hash (broken) | Fernet envelope encryption with KMS-wrapped key | **CRITICAL** |
| Client secrets | Argon2id hash | Acceptable (one-way hash) | OK |
| Connection | None (localhost) | TLS 1.3 with certificate pinning | HIGH |

### 2.7 Encryption in Transit

```ini
# postgresql.conf
ssl = on
ssl_cert_file = '/etc/postgresql/16/main/server.crt'
ssl_key_file = '/etc/postgresql/16/main/server.key'
ssl_ca_file = '/etc/postgresql/16/main/ca.crt'
ssl_min_protocol_version = 'TLSv1.3'
ssl_ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
```

**Application connection string:**
```
postgresql+asyncpg://user:pass@host:5432/db?ssl=verify-full&sslrootcert=/path/to/ca.pem
```

### 2.8 Secret Rotation Procedures

| Secret | Current Rotation | Required Rotation | Method |
|---|---|---|---|
| JWT signing keys | Manual (documented, not automated) | 90 days automated | HSM-backed, automated rotation script |
| Database passwords | Manual | 30 days | Vault dynamic secrets or automated rotation |
| Client secrets | On demand | 180 days | Admin endpoint + client notification |
| TOTP secrets | Per re-enrollment | On compromise | Fernet key rotation + re-encryption |
| Redis password | None (no auth) | 30 days | requirepass + ACL |
| APP_SECRET_KEY | Empty string | 30 days | Vault-generated, environment injection |
| API keys | None | 90 days | OAuth client credentials rotation |

---

## 3. Identity & Access Management Design

### 3.1 RBAC — Current State

```python
# Current: comma-separated strings
user.roles = "admin,editor"
role.permissions = "users:read,users:write,clients:write"
```

**Gaps:**
- No role hierarchy
- No permission allowlist
- No denial rules
- String parsing is fragile (whitespace, duplicates)
- No audit of permission grants/revocations

### 3.2 RBAC — Target Design

```sql
-- Normalized role-permission model
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    description TEXT,
    UNIQUE(resource, action)
);

CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Predefined permissions (allowlist)
INSERT INTO permissions (resource, action) VALUES
    ('users', 'read'), ('users', 'write'), ('users', 'delete'),
    ('clients', 'read'), ('clients', 'write'), ('clients', 'delete'),
    ('tenants', 'read'), ('tenants', 'write'),
    ('admin', 'read'), ('admin', 'write'),
    ('audit', 'read'), ('audit', 'export'),
    ('mfa', 'read'), ('mfa', 'write'),
    ('sessions', 'read'), ('sessions', 'revoke');
```

### 3.3 ABAC — Target Design

```sql
CREATE TABLE access_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    resource VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    condition JSONB NOT NULL,  -- e.g., {"time": {"after": "08:00", "before": "18:00"}, "ip_range": "10.0.0.0/8"}
    effect VARCHAR(16) NOT NULL DEFAULT 'allow',  -- allow | deny
    priority INTEGER NOT NULL DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 3.4 Multi-Tenant Authorization

**Current:** tenant_id on every table, filtered at repository level.
**Required additions:**
- RLS policies (see Section 2.3)
- Token claims include `tid` (tenant_id) — **already implemented**
- Cross-tenant operations explicitly denied — **already implemented**
- Tenant-scoped audit trail — **already implemented**

### 3.5 MFA Requirements

**CRITICAL BUG:** TOTP verification is fundamentally broken. Secrets are hashed with Argon2id on enrollment (irreversible), but verification attempts to use the hash as the raw TOTP secret. This means MFA can never work.

**Fix required — envelope encryption:**

```python
from cryptography.fernet import Fernet


class MFASecretEncryptor:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt(self, encrypted: str) -> str:
        return self._fernet.decrypt(encrypted.encode()).decode()


# In MFAService.enroll_totp:
encrypted_secret = encryptor.encrypt(secret)
factor.secret_hash = encrypted_secret  # Rename column to secret_encrypted

# In MFAService.verify_totp:
raw_secret = encryptor.decrypt(factor.secret_encrypted)
totp = pyotp.TOTP(raw_secret, digits=settings.mfa_totp_digits, interval=settings.mfa_totp_period)
```

**MFA enforcement policy:**
- Admin endpoints must require MFA (currently not enforced)
- Password reset must require MFA
- Token revocation for another user must require MFA
- MFA bypass codes (recovery codes) must be generated and stored hashed

### 3.6 Session Management

**Current:** Server-side sessions with idle (30min) and absolute (24h) timeouts.

**Gaps:**
- No IP binding (session can be used from any IP after creation)
- No User-Agent binding
- No concurrent session limit
- No session fixation protection (session ID not rotated on auth)
- No background cleanup of expired sessions
- Sessions stored in PostgreSQL (should be Redis for performance)

### 3.7 Token Lifecycle

| Token Type | Current TTL | Recommended TTL | Storage |
|---|---|---|---|
| Access token (JWT) | 15 minutes | 5-10 minutes | Stateless (JWT) |
| Refresh token | 30 days | 7 days (sensitive) / 30 days (standard) | DB (SHA-256 hash) |
| Authorization code | 5 minutes | 5 minutes | DB (SHA-256 hash) |
| Session | 24h absolute | 8h absolute (admin) / 24h (user) | DB |

### 3.8 OIDC Flows — Gap Analysis

| Flow | Implemented | Gap |
|---|---|---|
| Authorization Code + PKCE | Yes | No login UI, no consent screen |
| Client Credentials | Yes | None |
| Refresh Token Rotation | Yes | None |
| Token Revocation (RFC 7009) | Yes | None |
| Token Introspection (RFC 7662) | Yes | None |
| OIDC Discovery | Yes | Endpoint at /api/oidc/ (non-standard prefix) |
| JWKS | Yes | None |
| UserInfo | Yes | None |
| ID Token | No | **CRITICAL** — Not issued at all |
| Back-Channel Logout | No | Required for SOC 2 |
| Front-Channel Logout | No | Recommended |
| DPoP | No | Recommended for sender-constrained tokens |

### 3.9 Service-to-Service Authentication

**Current:** No service-to-service auth. All services would use client_credentials grant.

**Required:** mTLS with internal PKI:

```
Internal CA (cfssl or step-ca)
├── jol-auth service cert
├── jol-hub service cert
├── jol-ai service cert
└── PostgreSQL server cert

Service-to-service: mTLS + JWT bearer tokens
Service-to-database: TLS + scram-sha-256
```

---

## 4. Audit Architecture

### 4.1 Current State

- Audit events stored in `audit_events` table within `jol_identity` database
- Append-only enforced at application level only (no DB constraint)
- No request ID correlation
- No cryptographic integrity (hash chaining)
- No retention policy enforcement
- No separate `jol_audit` database usage

### 4.2 Immutable Audit Events — Required Design

```sql
-- In jol_audit database (NOT jol_identity)
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    action VARCHAR(64) NOT NULL,
    actor_id UUID,
    target_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    request_id VARCHAR(64),           -- NEW: correlation ID
    prev_hash VARCHAR(64),            -- NEW: hash chaining
    event_hash VARCHAR(64) NOT NULL,  -- NEW: SHA-256 of (prev_hash + event_data)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Block UPDATE and DELETE via trigger
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit events are immutable. INSERT only.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER audit_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Hash chaining trigger
CREATE OR REPLACE FUNCTION calculate_audit_hash()
RETURNS TRIGGER AS $$
DECLARE
    last_hash VARCHAR(64);
BEGIN
    SELECT event_hash INTO last_hash FROM audit_events ORDER BY created_at DESC LIMIT 1;
    NEW.prev_hash := COALESCE(last_hash, '0'::varchar);
    NEW.event_hash := encode(
        digest(
            NEW.prev_hash || NEW.tenant_id::text || NEW.action || NEW.actor_id::text || NEW.details::text,
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_hash_chain
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION calculate_audit_hash();
```

### 4.3 SOC 2 Controls Mapping

| SOC 2 Control | Audit Event | Current | Required |
|---|---|---|---|
| CC6.1 (Logical Access) | login.success, login.failure | Logged | Add request_id, add IP geolocation |
| CC6.2 (User Authentication) | mfa.enrolled, mfa.removed | Logged | Add MFA challenge events |
| CC6.3 (Access Restrictions) | admin.action | Logged | Add permission.granted, permission.revoked |
| CC7.1 (System Monitoring) | token.issued, token.revoked | Logged | Add api.access logs for sensitive endpoints |
| CC7.2 (Anomaly Detection) | — | **MISSING** | Add anomaly detection on login patterns |
| CC8.1 (Change Management) | — | **MISSING** | Add config.change, schema.migration events |

### 4.4 ISO 27001 Controls Mapping

| ISO 27001 Control | Audit Requirement | Status |
|---|---|---|
| A.8.15 (Logging) | Log all security-relevant events | Partial — missing config changes |
| A.8.16 (Monitoring) | Detect anomalous activities | **MISSING** |
| A.5.34 (Privacy) | Log PII access | **MISSING** |
| A.8.24 (Cryptography) | Log key management operations | Partial — key rotation not logged |
| A.5.15 (Access Control) | Log access rights changes | **MISSING** — role grants not audited |

### 4.5 GDPR Accountability

| GDPR Article | Audit Requirement | Status |
|---|---|---|
| Art. 5(2) (Accountability) | Demonstrate compliance | **MISSING** — no compliance dashboard |
| Art. 30 (Records of Processing) | Maintain processing records | **MISSING** |
| Art. 33 (Breach Notification) | Log security incidents | Partial — incident.runbook exists, no automated logging |
| Art. 35 (DPIA) | Data protection impact assessment | Template exists, not completed |

### 4.6 Retention Policies

| Data Type | Retention Period | Legal Basis | Deletion Method |
|---|---|---|---|
| Audit events (security) | 7 years | SOC 2, ISO 27001 | Archive + delete |
| Login events | 2 years | SOC 2 CC6.1 | Delete after retention |
| Token records (expired) | 90 days | Operational | Automated cleanup job |
| Session records (expired) | 30 days | Operational | Automated cleanup job |
| User data (after deletion) | 30 days grace, then anonymize | GDPR Art. 17 | Soft delete → anonymize |
| Authorization codes (consumed) | 7 days | Fraud investigation | Delete |

---

## 5. GDPR Architecture

### 5.1 Data Inventory

| Data Category | Location | Legal Basis | Retention | Current Status |
|---|---|---|---|---|
| User email | jol_identity.users | Consent / Legitimate interest | Account lifetime + 30 days | Stored, no consent tracking |
| User password hash | jol_identity.users | Contract | Account lifetime | Argon2id hashed |
| User display name | jol_identity.users | Consent | Account lifetime | Plaintext |
| User roles | jol_identity.users | Legitimate interest | Account lifetime | Comma-separated |
| Session data (IP, UA) | jol_identity.sessions | Legitimate interest | 30 days | Stored, no cleanup |
| Audit logs (IP, UA) | jol_identity.audit_events | Legal obligation | 7 years | Stored |
| TOTP secrets | jol_identity.mfa_factors | Consent | Until unenrolled | **BROKEN** — hashed irreversibly |
| OAuth client secrets | jol_identity.clients | Contract | Client lifetime | Argon2id hashed |
| Refresh tokens | jol_identity.refresh_tokens | Contract | 30 days | SHA-256 hashed |

### 5.2 Data Classification

| Classification | Examples | Encryption | Access Control | Audit |
|---|---|---|---|---|
| **Public** | JWKS, OIDC discovery | None | Public | None |
| **Internal** | Tenant metadata, client names | TLS in transit | Authenticated | SELECT |
| **Confidential** | User emails, roles | TLS + at-rest | RBAC | SELECT + INSERT |
| **Restricted** | Passwords, TOTP secrets, tokens | TLS + at-rest + envelope encryption | Service-only | INSERT only |
| **Regulated (GDPR)** | PII (email, IP, name) | TLS + at-rest + encryption | RBAC + RLS | Full audit |

### 5.3 Consent Management — Required Design

```sql
CREATE TABLE consent_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_type VARCHAR(64) NOT NULL,  -- 'terms', 'privacy', 'marketing', 'analytics'
    consent_version VARCHAR(32) NOT NULL,
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 5.4 Right-to-Access Workflow (GDPR Art. 15)

```
1. User submits DSAR (Data Subject Access Request) via web form
2. Admin verifies identity (MFA required)
3. System queries all tables for user's data:
   - users, sessions, tokens, refresh_tokens, mfa_factors, audit_events
4. System generates JSON export with all personal data
5. Deliver to user within 30 days (GDPR requirement)
6. Log the DSAR in audit_events (action: gdpr.access_request)
```

### 5.5 Right-to-Erasure Workflow (GDPR Art. 17)

```
1. User submits deletion request
2. Admin verifies identity (MFA required)
3. Soft-delete user (set deleted_at = NOW())
4. 30-day grace period (user can cancel)
5. After grace period:
   a. Anonymize user record (email = 'anonymized', display_name = NULL)
   b. Revoke all tokens and sessions
   c. Delete mfa_factors
   d. Anonymize audit_events (actor_id = NULL, ip_address = NULL)
   e. Keep audit trail with anonymized references (legal obligation)
6. Log the erasure in audit_events (action: gdpr.erasure_completed)
```

**Required schema changes:**

```sql
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN anonymized_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN consent_version VARCHAR(32);
ALTER TABLE users ADD COLUMN retention_policy VARCHAR(64) DEFAULT 'standard';
```

### 5.6 Data Retention Schedule

```sql
-- Automated retention job (pg_cron or Celery beat)
-- Run daily at 03:00 UTC

-- Delete expired tokens (90 days)
DELETE FROM tokens WHERE expires_at < NOW() - INTERVAL '90 days';

-- Delete expired sessions (30 days)
DELETE FROM sessions WHERE expires_at < NOW() - INTERVAL '30 days';

-- Delete consumed authorization codes (7 days)
DELETE FROM authorization_codes WHERE consumed = true AND created_at < NOW() - INTERVAL '7 days';

-- Anonymize deleted users after grace period
UPDATE users SET
    email = 'anonymized_' || id::text || '@deleted.local',
    display_name = NULL,
    password_hash = 'ANONYMIZED',
    anonymized_at = NOW()
WHERE deleted_at IS NOT NULL
  AND deleted_at < NOW() - INTERVAL '30 days'
  AND anonymized_at IS NULL;
```

---

## 6. Multi-Tenant SaaS Architecture

### 6.1 tenant_id Strategy

**Current:** UUID primary key on tenants table, FK on all tables, application-layer filtering.
**Required:** Database-level RLS (see Section 2.3) as defense-in-depth.

### 6.2 organization_id Strategy

**GAP:** The `organization_id` concept from the architecture document is NOT implemented in jol-auth. This is a concept for `jol_lt_platform_prod` (the business database), not the identity database.

**For jol_identity:** `tenant_id` IS the organization identifier. Each tenant = one organization.

**For jol_lt_platform_prod:** Must add `organization_id` to all business tables with RLS policies.

### 6.3 PostgreSQL RLS Policies

See Section 2.3 for implementation details.

**Additional cross-tenant protection:**

```sql
-- Prevent cross-tenant queries at connection level
CREATE OR REPLACE FUNCTION enforce_tenant_context()
RETURNS void AS $$
BEGIN
    IF current_setting('app.tenant_id', true) IS NULL THEN
        RAISE EXCEPTION 'Tenant context not set. All queries must set app.tenant_id.';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Call this function at the start of every session
-- Application must execute: SELECT enforce_tenant_context();
```

### 6.4 Domain Routing

**Not implemented.** Required for production:

```
User visits: parish.lt
  → NGINX resolves domain to organization_id
  → Sets X-Tenant-ID header
  → FastAPI processes request in tenant context

User visits: cathedral.lt
  → NGINX resolves to different organization_id
  → Different tenant context
```

**Implementation:**
```python
# Domain-to-tenant resolution table in jol_platform_control
CREATE TABLE domain_mappings (
    domain VARCHAR(255) PRIMARY KEY,
    tenant_id UUID NOT NULL,
    organization_id UUID,
    ssl_cert_path VARCHAR(512),
    is_active BOOLEAN DEFAULT true
);
```

### 6.5 Country Expansion Strategy

```
Current: jol_lt_platform_prod (Lithuania)
Future:  jol_lv_platform_prod (Latvia)
         jol_ee_platform_prod (Estonia)
         jol_de_platform_prod (Germany)
         ...

Template: jol_template (IS_TEMPLATE = true)
Cloning:  CREATE DATABASE jol_lv_platform_prod TEMPLATE jol_template;

Shared services (all countries):
├── jol_platform_control (global)
├── jol_identity (global, tenant-scoped)
├── jol_audit (global, tenant-scoped)
├── jol_ai_platform (global, tenant-scoped)
└── jol_media_storage (global, tenant-scoped)
```

---

## 7. Infrastructure Architecture

### 7.1 Docker — Current State

```dockerfile
# Current Dockerfile — BASIC, not production-ready
FROM python:3.12-slim
# No multi-stage build
# No .dockerignore
# No health check in Dockerfile
# Runs as root (no USER directive)
# No signal handling (PID 1 issue)
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
# Migrations run on every container start (dangerous in HA)
```

### 7.2 Docker — Required Changes

```dockerfile
# Multi-stage build
FROM python:3.12-slim AS builder
# ... build wheels ...

FROM python:3.12-slim AS runtime
# Non-root user
RUN useradd -m -u 1000 jol
USER jol
# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1
# Proper signal handling
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
# Migrations as separate init container, not in app CMD
```

### 7.3 Kubernetes Readiness

**Current:** None. No K8s manifests, no Helm chart, no health probes.

**Required:**

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jol-auth
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: jol-auth
          image: ghcr.io/journeyoflife/jol-auth:latest
          ports:
            - containerPort: 8000
          envFrom:
            - secretRef:
                name: jol-auth-secrets
          livenessProbe:
            httpGet:
              path: /api/health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/health
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
```

### 7.4 MinIO Integration

**Required for:** File storage (jol_media_storage metadata only).

```yaml
# docker-compose.yml addition
minio:
  image: minio/minio:latest
  command: server /data --console-address ":9001"
  environment:
    MINIO_ROOT_USER: ${MINIO_ROOT_USER}
    MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
  volumes:
    - minio_data:/data
  ports:
    - "9000:9000"
    - "9001:9001"
```

### 7.5 Redis — Required Changes

**Current:** No authentication, no TLS, used only for (broken) rate limiting stub.

**Required:**
```ini
# redis.conf
requirepass ${REDIS_PASSWORD}
tls-port 6379
port 0
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
maxmemory 256mb
maxmemory-policy allkeys-lru
```

**Use cases:**
- Rate limiting (sliding window)
- Session storage (move from PostgreSQL)
- Token blacklist (for fast revocation checks)
- Distributed locks (for concurrent operations)

### 7.6 NGINX Configuration

```nginx
upstream jol_auth {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name auth.journeyoflife.org;

    ssl_certificate /etc/ssl/certs/auth.journeyoflife.org.crt;
    ssl_certificate_key /etc/ssl/private/auth.journeyoflife.org.key;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    location /api/oauth/token {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://jol_auth;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://jol_auth;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 7.7 Monitoring

**Required stack:**
- **Metrics:** Prometheus + Grafana
- **Logs:** Loki or ELK
- **Traces:** OpenTelemetry Collector + Jaeger/Tempo
- **Alerting:** AlertManager → PagerDuty/Slack

**Key metrics to implement:**
- `jol_auth_login_total{tenant_id, status}`
- `jol_auth_token_issued_total{grant_type}`
- `jol_auth_token_revoked_total`
- `jol_auth_request_duration_seconds{endpoint}`
- `jol_auth_db_connection_pool{state}`
- `jol_auth_rate_limit_rejected_total`

### 7.8 Disaster Recovery

| Component | RPO | RTO | Strategy |
|---|---|---|---|
| PostgreSQL | 5 min | 2 hr | WAL streaming + pgBackRest |
| Redis | 15 min | 15 min | AOF persistence + replica |
| MinIO | 1 hr | 4 hr | Versioning + cross-region replication |
| Application | 0 | 15 min | Multi-zone deployment |
| Configuration | 0 | 5 min | GitOps (ArgoCD) |

---

## 8. AI Platform Architecture

### 8.1 AI Agent Permissions

**Current:** `jol_ai_platform` database exists but no schema, no tables, no services.

**Required design:**
```sql
-- In jol_ai_platform
CREATE TABLE ai_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    allowed_scopes TEXT[] NOT NULL,  -- ['users:read', 'crm:read']
    denied_resources TEXT[] DEFAULT '{}',
    max_tokens_per_request INTEGER DEFAULT 4096,
    rate_limit_per_minute INTEGER DEFAULT 60,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE ai_agent_credentials (
    agent_id UUID REFERENCES ai_agents(id) ON DELETE CASCADE,
    client_id VARCHAR(128) NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    last_used_at TIMESTAMPTZ,
    PRIMARY KEY (agent_id)
);
```

### 8.2 Prompt Security

- Input sanitization (strip injection vectors)
- Output filtering (PII detection, redaction)
- Token budget enforcement
- Prompt logging (for audit)
- Deny-list of prohibited patterns

### 8.3 Data Leakage Prevention

- AI agents can only access data within their tenant scope
- RLS enforced on all AI queries
- PII fields (email, phone) redacted before LLM processing
- Response scrubbing (regex-based PII detection)

### 8.4 Auditability

- Every AI request logged with: agent_id, tenant_id, prompt_hash, response_hash, tokens_used
- Human approval workflow for high-privilege operations
- Rate limiting per agent
- Anomaly detection on query patterns

### 8.5 Human Approval Workflows

```
AI Agent → Proposes action (e.g., send email to 1000 users)
  → Creates approval_request in jol_ai_platform
  → Notifies human approver
  → Human approves/rejects
  → Action executed or cancelled
  → All steps audit-logged
```

---

## 9. Deliverables

### A. Gap Analysis

| # | Gap | Severity | Category | Effort |
|---|---|---|---|---|
| G01 | Rate limiting not implemented (NotImplementedError) | CRITICAL | Security | M |
| G02 | MFA TOTP verification broken (hashed secrets) | CRITICAL | Security | S |
| G03 | No database-level RLS (tenant isolation) | CRITICAL | Security | M |
| G04 | No ID token issuance (OIDC non-compliant) | CRITICAL | Compliance | M |
| G05 | Hardcoded credentials in docker-compose.yml | CRITICAL | Security | S |
| G06 | No audit immutability (DB triggers) | HIGH | Compliance | S |
| G07 | Audit events in wrong database (jol_identity not jol_audit) | HIGH | Architecture | M |
| G08 | No request_id in audit events | HIGH | Compliance | S |
| G09 | No CSRF protection | HIGH | Security | S |
| G10 | No account lockout policy | HIGH | Security | S |
| G11 | No session IP/UA binding | HIGH | Security | M |
| G12 | No session cleanup job | HIGH | Operations | S |
| G13 | OpenTelemetry stub (no tracing) | HIGH | Operations | M |
| G14 | No encryption at rest | HIGH | Security | M |
| G15 | No TLS on DB connections | HIGH | Security | S |
| G16 | Redis no auth, no TLS | HIGH | Security | S |
| G17 | Dockerfile runs as root | HIGH | Security | S |
| G18 | No GDPR consent tracking | HIGH | Compliance | M |
| G19 | No soft delete / anonymization | HIGH | GDPR | M |
| G20 | No redirect URI scheme validation | MEDIUM | Security | S |
| G21 | Permission strings not normalized | MEDIUM | Architecture | M |
| G22 | No role hierarchy | MEDIUM | IAM | M |
| G23 | No ABAC | MEDIUM | IAM | L |
| G24 | RSA key 2048-bit (should be 3072+) | MEDIUM | Security | S |
| G25 | No HSM/key vault integration | MEDIUM | Security | L |
| G26 | No K8s manifests | MEDIUM | Operations | M |
| G27 | No monitoring/alerting | MEDIUM | Operations | L |
| G28 | No backup automation | MEDIUM | Operations | M |
| G29 | No PITR | MEDIUM | Operations | M |
| G30 | No service-to-service mTLS | MEDIUM | Security | L |

### B. Risk Register

| Risk ID | Description | Likelihood | Impact | Risk Score | Mitigation |
|---|---|---|---|---|---|
| R01 | Credential stuffing attack (no rate limiting) | HIGH | HIGH | **CRITICAL** | Implement Redis-backed rate limiter (G01) |
| R02 | Cross-tenant data breach (no RLS) | MEDIUM | CRITICAL | **CRITICAL** | Implement RLS policies (G03) |
| R03 | MFA bypass (broken TOTP) | HIGH | HIGH | **CRITICAL** | Fix TOTP with envelope encryption (G02) |
| R04 | OIDC non-compliance (no ID token) | HIGH | HIGH | **CRITICAL** | Implement ID token issuance (G04) |
| R05 | Audit log tampering | MEDIUM | HIGH | **HIGH** | Add DB triggers for immutability (G06) |
| R06 | Credential exposure in version control | HIGH | HIGH | **CRITICAL** | Move to Vault, remove from compose (G05) |
| R07 | Session hijacking (no IP binding) | MEDIUM | HIGH | **HIGH** | Add IP/UA fingerprinting (G11) |
| R08 | GDPR non-compliance (no consent tracking) | HIGH | HIGH | **CRITICAL** | Implement consent management (G18) |
| R09 | Key compromise (no HSM, 2048-bit) | LOW | CRITICAL | **HIGH** | Migrate to HSM, upgrade to 3072-bit (G24, G25) |
| R10 | Data loss (no automated backups) | MEDIUM | CRITICAL | **HIGH** | Implement pgBackRest + WAL archiving (G28, G29) |

### C. Security Control Matrix

| Control ID | Framework | Requirement | Implementation | Status |
|---|---|---|---|---|
| OWASP-ASVS-2.1.1 | ASVS L2 | Password complexity | 12+ chars, upper/lower/digit/special | PASS |
| OWASP-ASVS-2.1.4 | ASVS L2 | Password hashing (Argon2id) | Argon2id with OWASP params | PASS |
| OWASP-ASVS-2.5.1 | ASVS L2 | Rate limiting on auth endpoints | Stub implementation | **FAIL** |
| OWASP-ASVS-2.5.2 | ASVS L2 | Account lockout | Not implemented | **FAIL** |
| OWASP-ASVS-2.7.1 | ASVS L2 | Session timeout | Idle 30min, absolute 24h | PASS |
| OWASP-ASVS-3.1.1 | ASVS L2 | Token-based session | JWT + opaque refresh | PASS |
| OWASP-ASVS-3.4.1 | ASVS L2 | Session token entropy | UUID4 + secrets.token_urlsafe | PASS |
| OWASP-ASVS-4.1.1 | ASVS L2 | Access control on all endpoints | require_permission dependency | PASS |
| OWASP-ASVS-4.1.3 | ASVS L2 | Multi-tenant data isolation | Application-layer only | **PARTIAL** |
| OWASP-ASVS-6.2.1 | ASVS L2 | JWT verification | RS256 + kid + iss/aud/exp | PASS |
| OWASP-ASVS-6.2.2 | ASVS L2 | JWT key rotation | 90-day documented (not automated) | **PARTIAL** |
| OWASP-ASVS-7.1.1 | ASVS L2 | TLS enforcement | HSTS header (assumes NGINX) | **PARTIAL** |
| OWASP-ASVS-8.1.1 | ASVS L2 | Data protection at rest | None | **FAIL** |
| OWASP-ASVS-8.3.1 | ASVS L2 | Sensitive data encryption in transit | TLS to NGINX only | **PARTIAL** |
| OWASP-ASVS-9.1.1 | ASVS L2 | Audit logging | Implemented but not immutable | **PARTIAL** |
| OWASP-ASVS-9.1.2 | ASVS L2 | Audit log protection | Append-only at app layer | **PARTIAL** |
| SOC2-CC6.1 | SOC 2 | Logical and physical access | Implemented | **PARTIAL** |
| SOC2-CC6.6 | SOC 2 | Boundary protection | No WAF, no rate limiting | **FAIL** |
| SOC2-CC7.1 | SOC 2 | System monitoring | No monitoring | **FAIL** |
| SOC2-CC7.2 | SOC 2 | Anomaly detection | Not implemented | **FAIL** |
| ISO-A.8.15 | ISO 27001 | Logging | Partial implementation | **PARTIAL** |
| ISO-A.8.24 | ISO 27001 | Use of cryptography | RS256, Argon2id; no HSM, no at-rest | **PARTIAL** |
| GDPR-Art.5 | GDPR | Data minimization | Not assessed | **FAIL** |
| GDPR-Art.7 | GDPR | Consent management | Not implemented | **FAIL** |
| GDPR-Art.17 | GDPR | Right to erasure | Not implemented | **FAIL** |
| GDPR-Art.25 | GDPR | Privacy by design | Partial (tenant isolation) | **PARTIAL** |
| GDPR-Art.30 | GDPR | Records of processing | Not maintained | **FAIL** |
| GDPR-Art.32 | GDPR | Security of processing | No encryption at rest | **FAIL** |
| GDPR-Art.33 | GDPR | Breach notification | Runbook exists, no automation | **PARTIAL** |

### D. Database Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      PostgreSQL 16 Cluster                               │
│                   (scram-sha-256, TLS 1.3)                               │
│                                                                         │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────┐ │
│  │ jol_platform_control│  │ jol_identity        │  │ jol_audit        │ │
│  │                     │  │                     │  │                  │ │
│  │ countries           │  │ tenants      [RLS]  │  │ audit_events     │ │
│  │ regions             │  │ users        [RLS]  │  │   (immutable)    │ │
│  │ dioceses            │  │ roles        [RLS]  │  │   (hash-chained) │ │
│  │ deaneries           │  │ sessions     [RLS]  │  │   (trigger-      │ │
│  │ organizations       │  │ tokens       [RLS]  │  │    protected)    │ │
│  │ tenants             │  │ refresh_tok  [RLS]  │  │                  │ │
│  │ subscriptions       │  │ clients      [RLS]  │  │ Owner:           │ │
│  │ domains             │  │ mfa_factors  [RLS]  │  │  jol_audit_user  │ │
│  │ deployment_registry │  │ auth_codes   [RLS]  │  │  (INSERT only)   │ │
│  │ audit_registry      │  │ audit_events [RLS]  │  │                  │ │
│  │                     │  │                     │  │ Reader:          │ │
│  │ Owner:              │  │ Owner:              │  │  jol_audit_reader│ │
│  │  jol_control_user   │  │  jol_identity_user  │  │  (SELECT only)   │ │
│  └─────────────────────┘  └─────────────────────┘  └─────────────────┘ │
│                                                                         │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────┐ │
│  │ jol_ai_platform     │  │ jol_media_storage   │  │jol_lt_platform  │ │
│  │                     │  │                     │  │     _prod       │ │
│  │ ai_agents     [RLS] │  │ media_files   [RLS] │  │                 │ │
│  │ ai_requests   [RLS] │  │ media_versions[RLS] │  │ users     [RLS]  │ │
│  │ ai_approvals  [RLS] │  │ buckets       [RLS] │  │ websites  [RLS]  │ │
│  │ model_registry[RLS] │  │                     │  │ crm_*     [RLS]  │ │
│  │                     │  │ Owner:              │  │ finance   [RLS]  │ │
│  │ Owner:              │  │  jol_media_user     │  │ analytics [RLS]  │ │
│  │  jol_ai_user        │  │                     │  │ documents [RLS]  │ │
│  └─────────────────────┘  └─────────────────────┘  │                 │ │
│                                                    │ Owner:          │ │
│  ┌─────────────────────┐                           │  jol_lt_app_user│ │
│  │ jol_template        │                           └─────────────────┘ │
│  │ (IS_TEMPLATE=true)  │                                               │
│  │ Clone for new       │           Backup: pgBackRest + WAL archiving  │
│  │ country databases   │           PITR: 30-day recovery window        │
│  └─────────────────────┘           Encryption: AES-256 at rest          │
└─────────────────────────────────────────────────────────────────────────┘
```

### E. Identity Architecture Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   User       │     │  Admin       │     │  AI Agent    │
│   Browser    │     │  Browser     │     │  (Service)   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  HTTPS + PKCE      │  HTTPS + MFA       │  mTLS + Client Creds
       ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────────┐
│                    NGINX (TLS 1.3)                        │
│              Rate Limiting + WAF + HSTS                  │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                  jol-auth (FastAPI)                       │
│                                                          │
│  Middleware: RequestID → SecurityHeaders →               │
│              TenantResolution → AuditContext             │
│                                                          │
│  Endpoints:                                              │
│  ├── /api/oauth/authorize  (Auth Code + PKCE)           │
│  ├── /api/oauth/token      (4 grant types)              │
│  ├── /api/oauth/revoke     (RFC 7009)                   │
│  ├── /api/oauth/introspect (RFC 7662)                   │
│  ├── /api/oidc/.well-known/openid-configuration         │
│  ├── /api/oidc/userinfo                                  │
│  ├── /api/jwks/                                          │
│  ├── /api/users/                                         │
│  ├── /api/sessions/                                      │
│  ├── /api/mfa/                                           │
│  ├── /api/admin/                                         │
│  └── /api/tenants/                                       │
│                                                          │
│  Security:                                               │
│  ├── RS256 JWT signing (HSM-backed)                      │
│  ├── PKCE S256 enforcement                               │
│  ├── Refresh token rotation + family revocation          │
│  ├── RBAC with tenant-scoped permissions                 │
│  ├── MFA (TOTP with envelope encryption)                 │
│  └── Rate limiting (Redis sliding window)                │
└──────┬───────────────┬───────────────────────────────────┘
       │               │
       ▼               ▼
┌──────────┐   ┌──────────────────┐
│  Redis   │   │  PostgreSQL       │
│ (TLS)    │   │  jol_identity     │
│          │   │  (RLS enabled)    │
│ - rate   │   │                   │
│   limit  │   │  + jol_audit      │
│ - session│   │    (immutable)    │
│ - cache  │   │                   │
└──────────┘   └──────────────────┘
```

### F. Deployment Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Production Environment                       │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Kubernetes Cluster                    │   │
│  │                                                         │   │
│  │  ┌─── Namespace: jol-auth ───┐                         │   │
│  │  │                           │                         │   │
│  │  │  ┌─────────────────────┐  │  ┌──────────────────┐   │   │
│  │  │  │ jol-auth (3 replicas)│  │  │  NGINX Ingress   │   │   │
│  │  │  │  + liveness probe   │  │  │  (TLS 1.3, WAF)  │   │   │
│  │  │  │  + readiness probe  │  │  │  Rate limiting   │   │   │
│  │  │  └─────────────────────┘  │  └──────────────────┘   │   │
│  │  │                           │                         │   │
│  │  │  ┌─────────────────────┐  │                         │   │
│  │  │  │ migration job       │  │                         │   │
│  │  │  │ (init container)    │  │                         │   │
│  │  │  └─────────────────────┘  │                         │   │
│  │  └───────────────────────────┘                         │   │
│  │                                                         │   │
│  │  ┌─── Namespace: data ────────┐                        │   │
│  │  │ PostgreSQL (StatefulSet)   │  Redis (StatefulSet)   │   │
│  │  │  + WAL archiving           │  + AOF persistence     │   │
│  │  │  + pgBackRest sidecar      │  + TLS                 │   │
│  │  │  + 3 replicas (1 Primary)  │  + 2 replicas          │   │
│  │  └────────────────────────────┘                        │   │
│  │                                                         │   │
│  │  ┌─── Namespace: storage ───┐                          │   │
│  │  │ MinIO (S3-compatible)    │                          │   │
│  │  │  + versioning            │                          │   │
│  │  │  + cross-region replica  │                          │   │
│  │  └──────────────────────────┘                          │   │
│  │                                                         │   │
│  │  ┌─── Namespace: monitoring ─┐                         │   │
│  │  │ Prometheus + Grafana      │                         │   │
│  │  │ Loki (logs)               │                         │   │
│  │  │ AlertManager → PagerDuty  │                         │   │
│  │  └───────────────────────────┘                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─── External ────┐                                           │
│  │ HashiCorp Vault  │ (secret management)                      │
│  │ cert-manager     │ (TLS certificate automation)             │
│  │ ArgoCD           │ (GitOps deployment)                      │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

### G. 90-Day Production Readiness Roadmap

#### Days 1-14: Critical Security Fixes

| Day | Task | Owner | Deliverable |
|---|---|---|---|
| 1-2 | Fix MFA TOTP (envelope encryption with Fernet) | Backend | Working MFA |
| 1-3 | Implement Redis-backed rate limiter | Backend | Rate limiting on all endpoints |
| 2-4 | Remove hardcoded credentials from docker-compose.yml | DevOps | Vault-backed secrets |
| 3-5 | Implement ID token issuance (OIDC compliance) | Backend | ID tokens in auth response |
| 5-7 | Implement PostgreSQL RLS policies | DBA | RLS on all tenant tables |
| 7-10 | Add audit immutability triggers | DBA | Immutable audit_events table |
| 10-12 | Move audit to jol_audit database | Backend | Audit events in correct DB |
| 12-14 | Add request_id to audit events | Backend | Correlated audit trail |

#### Days 15-30: Hardening

| Day | Task | Owner | Deliverable |
|---|---|---|---|
| 15-17 | Implement account lockout policy | Backend | Lockout after 5 failed attempts |
| 17-19 | Add session IP/UA binding | Backend | Session hijacking protection |
| 19-21 | Implement session cleanup job | DevOps | Celery beat task |
| 20-22 | Add TLS to PostgreSQL connections | DevOps | TLS 1.3 on DB connections |
| 22-24 | Add auth + TLS to Redis | DevOps | Secured Redis |
| 24-26 | Fix Dockerfile (non-root, multi-stage) | DevOps | Production Dockerfile |
| 26-28 | Implement CSRF protection | Backend | CSRF tokens on form endpoints |
| 28-30 | Normalize RBAC (junction tables) | Backend | Normalized permissions |

#### Days 31-60: Compliance & Infrastructure

| Day | Task | Owner | Deliverable |
|---|---|---|---|
| 31-35 | GDPR consent tracking | Backend | consent_records table + API |
| 35-40 | GDPR right-to-erasure workflow | Backend | Soft delete + anonymization |
| 40-45 | Implement backup automation (pgBackRest) | DevOps | Automated backups + PITR |
| 45-50 | Deploy NGINX reverse proxy | DevOps | TLS termination + rate limiting |
| 50-55 | Implement OpenTelemetry tracing | Backend | Distributed tracing |
| 55-60 | Deploy monitoring stack | DevOps | Prometheus + Grafana + alerts |

#### Days 61-90: Scale & Advanced

| Day | Task | Owner | Deliverable |
|---|---|---|---|
| 61-65 | Kubernetes manifests + Helm chart | DevOps | K8s deployment ready |
| 65-70 | mTLS for service-to-service auth | DevOps | Internal PKI + mTLS |
| 70-75 | HSM integration for signing keys | Security | HSM-backed JWT signing |
| 75-80 | ABAC implementation | Backend | Attribute-based policies |
| 80-85 | Penetration testing preparation | Security | Test environment + scope |
| 85-90 | SOC 2 / ISO 27001 evidence collection | Compliance | Audit evidence package |

### H. Priority-Ranked Implementation Backlog

| Priority | ID | Task | Effort | Severity |
|---|---|---|---|---|
| **P0** | G02 | Fix MFA TOTP with envelope encryption | S | CRITICAL |
| **P0** | G01 | Implement Redis-backed rate limiter | M | CRITICAL |
| **P0** | G03 | Implement PostgreSQL RLS policies | M | CRITICAL |
| **P0** | G04 | Implement OIDC ID token issuance | M | CRITICAL |
| **P0** | G05 | Remove hardcoded credentials | S | CRITICAL |
| **P0** | G06 | Add audit immutability triggers | S | HIGH |
| **P0** | G07 | Move audit to jol_audit database | M | HIGH |
| **P0** | G08 | Add request_id to audit events | S | HIGH |
| **P1** | G09 | Add CSRF protection | S | HIGH |
| **P1** | G10 | Implement account lockout | S | HIGH |
| **P1** | G11 | Session IP/UA binding | M | HIGH |
| **P1** | G12 | Session cleanup job | S | HIGH |
| **P1** | G13 | OpenTelemetry implementation | M | HIGH |
| **P1** | G14 | Encryption at rest (LUKS) | M | HIGH |
| **P1** | G15 | TLS on DB connections | S | HIGH |
| **P1** | G16 | Redis auth + TLS | S | HIGH |
| **P1** | G17 | Dockerfile non-root + multi-stage | S | HIGH |
| **P1** | G18 | GDPR consent tracking | M | HIGH |
| **P1** | G19 | Soft delete + anonymization | M | HIGH |
| **P2** | G20 | Redirect URI scheme validation | S | MEDIUM |
| **P2** | G21 | Normalize RBAC junction tables | M | MEDIUM |
| **P2** | G22 | Role hierarchy | M | MEDIUM |
| **P2** | G23 | ABAC implementation | L | MEDIUM |
| **P2** | G24 | RSA 3072-bit keys | S | MEDIUM |
| **P2** | G25 | HSM/vault integration | L | MEDIUM |
| **P2** | G26 | Kubernetes manifests | M | MEDIUM |
| **P2** | G27 | Monitoring/alerting stack | L | MEDIUM |
| **P2** | G28 | Backup automation (pgBackRest) | M | MEDIUM |
| **P2** | G29 | PITR configuration | M | MEDIUM |
| **P2** | G30 | Service-to-service mTLS | L | MEDIUM |

**Legend:** S = 1-2 days, M = 3-5 days, L = 1-2 weeks

---

## Summary Assessment

**Current state:** The jol-auth codebase has a solid architectural foundation with strong cryptographic practices (RS256, Argon2id, PKCE, refresh token rotation) and a well-designed multi-tenant model at the application layer. However, it is **NOT production-ready** for SOC 2, GDPR, or ISO 27001 compliance.

**Critical blockers (5):**
1. Rate limiting is a stub — system is vulnerable to brute-force attacks
2. MFA TOTP is broken — secrets cannot be verified
3. No database-level RLS — tenant isolation depends entirely on application code
4. No OIDC ID token — OIDC specification non-compliant
5. Hardcoded credentials in version control

**Estimated effort to production readiness:** 90 days with a team of 3-4 engineers.

**Recommendation:** Do NOT deploy to production until all P0 items are resolved. Begin immediately with the 90-day roadmap.
