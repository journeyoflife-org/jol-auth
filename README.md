# jol-auth

> **The central identity plane for Journey Of Life.** Every JOL service — frontend, backend, marketplace, analytics, CRM sync — trusts `jol-auth` as the single source of truth for who a user is, what tenant they belong to, and what they are allowed to do. No other repository issues, validates, or re-implements token logic independently.

**Classification:** RESTRICTED
**Owner:** `@journeyoflife-org/security` + `@journeyoflife-org/platform-core`
**Status:**

***

## Purpose and Scope

`jol-auth` is the dedicated Authentication and Identity Management service for the Journey Of Life platform, serving approximately 400,000 religious institution websites across 27 EU countries. It exists so that authentication, authorization, tenant identity, and credential lifecycle are implemented **once, correctly, and centrally** — never duplicated inside individual application repositories.

### What this repository owns

- OAuth 2.0 authorization server behavior (RFC 6749)
- OpenID Connect identity layer (OpenID Connect Core 1.0)
- Authorization Server Metadata / OIDC Discovery documents (RFC 8414)
- JSON Web Key Set (JWKS) publication and rotation
- Multi-tenant Role-Based Access Control (RBAC)
- Session lifecycle for browser-based clients
- Token issuance, rotation, and revocation
- OAuth client registration and lifecycle
- Multi-factor authentication (MFA) enforcement for privileged operations
- Authentication and authorization audit logging

### What this repository does NOT own

- Business logic of any downstream service (`jol-backend-platform`, `jol-commerce-engine`, etc.)
- User-facing UI beyond the minimal login/consent screens required by OAuth/OIDC flows
- Tenant business data (church records, donations, CRM data) — `jol-auth` stores only identity and access data
- Payment processing, analytics, or CRM synchronization

### The Golden Rule

**No service may mint its own access tokens, validate signatures against its own keys, or maintain a parallel session store.** Every JOL service — internal or third-party-facing — must:

1. Redirect unauthenticated users to `jol-auth` for login.
2. Validate incoming tokens against `jol-auth`'s published JWKS endpoint.
3. Trust claims (`tenant_id`, `sub`, `roles`, `scope`) exactly as issued — never reconstruct or infer them independently.
4. Use the discovery document (`/.well-known/openid-configuration`) to locate endpoints dynamically rather than hardcoding URLs.

Any service found implementing local password checks, custom JWT signing, or independent session cookies outside `jol-auth` is a **compliance and security violation** and must be remediated immediately.

***

## Supported Flows

| Flow | Use Case | Status |
|------|----------|--------|
| Authorization Code + PKCE | Browser-based apps, SPAs, mobile clients | Required — default flow |
| Client Credentials | Service-to-service (e.g., `jol-analytics-ai` → `jol-backend-platform`) | Supported |
| Refresh Token (rotating) | Silent re-authentication for long-lived sessions | Supported — rotation mandatory |
| Device Authorization Grant | Headless/CLI tooling (e.g., `jol-scripts` operators) | Supported |
| Resource Owner Password Credentials | — | **Not supported** — deprecated by current OAuth security guidance |
| Implicit Grant | — | **Not supported** — deprecated by current OAuth security guidance |

### Standard endpoints

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/openid-configuration` | OIDC Discovery — clients must fetch this rather than hardcode paths |
| `/.well-known/jwks.json` | Public signing keys for token verification |
| `/oauth/authorize` | Authorization endpoint (Authorization Code + PKCE) |
| `/oauth/token` | Token issuance and refresh |
| `/oauth/revoke` | Token revocation |
| `/oauth/introspect` | Token introspection (internal services only) |
| `/oidc/userinfo` | Authenticated user claims |
| `/health` | Liveness/readiness probe |

Every downstream service integration MUST begin by fetching the discovery document — never assume endpoint paths. This is what allows `jol-auth` to rotate infrastructure, change signing algorithms, or relocate endpoints without breaking every client in the platform simultaneously.

***

## Tenant Isolation Model

Each of the ~400,000 institutions is a distinct tenant. Tenant isolation is enforced at every layer, not just at the API boundary.

### Isolation guarantees

- **No cross-tenant queries.** Every repository-layer query is scoped by `tenant_id` at construction time — there is no code path that can accidentally return another tenant's rows.
- **Tokens are tenant-bound.** Every access token, refresh token, and authorization code carries a `tenant_id` claim. A token issued for Tenant A is structurally invalid when presented against Tenant B's resources.
- **Sessions are tenant-bound.** Browser sessions are scoped to a single tenant context; switching tenants requires a new authentication event, not a client-side context swap.
- **Admin operations are tenant-explicit.** There is no "super admin bypass" that operates silently across tenants — cross-tenant administrative actions require an explicit, audited, elevated-privilege path.
- **Database-level defense in depth.** Tenant scoping is enforced in the repository layer AND validated in integration tests (`tests/security/test_no_cross_tenant_queries.py`) that assert no query can leak across tenant boundaries.

### RBAC model

| Role scope | Example | Applies to |
|-----------|---------|-----------|
| Tenant-level roles | `institution_admin`, `content_editor`, `viewer` | Scoped to one tenant only |
| Platform-level roles | `platform_operator`, `security_admin` | JOL staff only, requires MFA, fully audited |

Roles issue scoped claims into tokens. Downstream services must check `roles` and `scope` claims — they must never re-derive permissions from any other source.

***

## Token and Session Policy

| Token type | Lifetime | Rotation | Storage |
|-----------|----------|----------|---------|
| Access token | Short-lived (minutes) | N/A — reissued via refresh | Bearer, memory/HTTP-only, never localStorage |
| Refresh token | Longer-lived (days) | Rotated on every use; old token invalidated | HTTP-only, Secure, SameSite cookie or secure client store |
| Authorization code | Single-use, ~60 seconds | N/A | Never persisted client-side |
| Session cookie | Configurable, tenant-scoped | Regenerated on privilege change | HTTP-only, Secure, SameSite=Strict |

### Enforcement rules

- Access tokens are deliberately short-lived so that a leaked token has minimal blast radius — this is the "short-lived credentials" principle mandated by the platform architecture.
- Refresh token rotation means every refresh invalidates the prior token; reuse of an already-rotated refresh token is treated as a potential theft signal and triggers session revocation plus an audit event.
- All signing uses asymmetric keys (JWKS-published public keys); private signing keys never leave `jol-auth`'s key management boundary and are rotated on a defined schedule (see `docs/key-rotation.md`).
- Session cookies never use client-readable storage. `localStorage`/`sessionStorage` are explicitly disallowed for any token or session identifier across the platform.
- Revocation is immediate and centralized — revoking a session or token at `jol-auth` takes effect platform-wide; no downstream service caches validity beyond the token's own short lifetime.

***

## Local Development Steps

### Prerequisites

- Ubuntu 24.04
- Python 3.12
- PyCharm Professional
- PostgreSQL (local or Docker)
- Redis (local or Docker)
- GitHub SSH access with signed commits configured

### Setup

```bash
git clone git@github.com:journeyoflife-org/jol-auth.git /opt/jol/repos/jol-auth
cd /opt/jol/repos/jol-auth

git config commit.gpgsign true
git config user.email "your.email@journeyoflife.org"

python3.12 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -e .[dev]

pre-commit install --install-hooks

cp .env.example .env
# Edit .env — populate local PostgreSQL/Redis connection strings and
# a locally-generated signing key. NEVER commit a populated .env.

docker compose up -d postgres redis

alembic upgrade head
```

### Running locally

```bash
uvicorn app.main:app --reload --port 8443
```

Verify the service is alive and correctly publishing metadata:

```bash
curl http://localhost:8443/health
curl http://localhost:8443/.well-known/openid-configuration | jq
curl http://localhost:8443/.well-known/jwks.json | jq
```

### PyCharm configuration

- Interpreter: project-local `.venv`, Python 3.12
- Enable Ruff, mypy (strict on `app/`), and pytest as run configurations
- Enable Qodana local run before every push
- Configure the Git pre-push hook to run `make validate`

***

## Security and Compliance Obligations

`jol-auth` is the highest-blast-radius repository on the platform. A defect here compromises every tenant simultaneously.

### Mandatory controls

| Control | Requirement |
|---------|-------------|
| Secret management | No secrets in code or `.env` committed to git. Signing keys and DB credentials loaded from external secret storage in staging/production. |
| MFA | Required for all platform-level administrative operations. |
| Audit logging | Every authentication event, token issuance, revocation, and admin action is logged with actor, tenant, timestamp, and outcome. Logs never contain raw tokens, passwords, or OTP codes. |
| Least privilege | Scopes and roles issued are the minimum necessary for the requesting client and grant type. |
| Redirect URI validation | Exact-match validation only — no wildcard or partial-match redirect URIs are accepted. |
| PKCE | Required for all public/browser clients. |
| Dependency scanning | Dependabot + pip-audit on every PR. |
| Static analysis | Ruff (including Bandit security rules), mypy strict, CodeQL, Qodana — all required to pass before merge. |
| Secret scanning | TruffleHog full-history scan runs in CI and pre-commit; any verified finding blocks merge. |

### Compliance framework alignment

| Framework | Relevant obligation |
|-----------|---------------------|
| GDPR | Identity data (user records, session metadata) is personal data — Art. 30 RoPA entry required in `jol-compliance`; DPIA required before processing changes affecting authentication of EU data subjects. |
| ISO 27001:2022 | A.8.5 (secure authentication), A.8.24 (cryptography/key management), A.5.15 (access control) |
| SOC 2 | CC6.1 (logical access controls), CC6.2 (credential management), CC6.3 (least privilege), CC7.2 (audit logging) |

Any change to token lifetime, signing algorithm, tenant isolation logic, or admin privilege paths requires security review before merge — no exceptions, regardless of urgency.

***

## Validation and Conformance Expectations

No pull request merges into `main` without passing all of the following.

### Required local checks before push

```bash
make lint          # ruff + mypy strict
make test           # pytest with coverage threshold (core auth modules require higher coverage)
make scan           # trufflehog + bandit rules + pip-audit
make validate       # lint + test + scan combined
make conformance    # discovery document, JWKS, and OAuth/OIDC flow validation
```

### Required CI gates

| Workflow | Blocks merge on |
|----------|-----------------|
| `ci.yml` | Lint failure, test failure, coverage below threshold |
| `compliance-check.yml` | Any verified secret, prohibited field in schema |
| `codeql.yml` | Any high/critical static analysis finding |
| `oidc-conformance.yml` | Discovery document malformed, JWKS unreachable, unsupported flow regressions |

### Tenant isolation is a release blocker

`tests/security/test_no_cross_tenant_queries.py` must pass on every build. A failure here is treated with the same severity as a secret leak — the build fails, and the change cannot merge under any circumstance until resolved.

### Non-negotiable review triggers

The following changes always require `@journeyoflife-org/security` sign-off in addition to standard code review:

- Token lifetime or rotation policy changes
- Signing key algorithm or key management changes
- New OAuth grant type support
- RBAC/scope model changes
- Any change touching `app/core/tenant_context.py` or `app/security/`

***

## Incident Reporting Path

**Do not open a public GitHub issue for any suspected authentication or identity vulnerability.**

| Severity | Example | Action |
|----------|---------|--------|
| P1 — Critical | Token forgery, cross-tenant data exposure, signing key compromise | Email security@journeyoflife.org immediately. 4-hour acknowledgement SLA. Rotate affected keys/tokens on confirmation. |
| P2 — High | Auth bypass, privilege escalation, session fixation | Email security@journeyoflife.org. 24-hour acknowledgement SLA. |
| P3 — Medium/Low | Non-exploitable hardening gaps, documentation errors | Standard issue tracker with `security` label. |

### If personal data exposure is suspected

Any incident involving unauthorized access to user identity records, session data, or authentication logs must be escalated as a potential GDPR Art. 33 breach. The 72-hour supervisory authority notification clock starts from confirmed discovery, not from full investigation completion. Follow the incident procedure documented in `jol-compliance` and notify the DPO immediately via security@journeyoflife.org.

### Suspected signing key compromise

```bash
# 1. Do not attempt to "quietly" rotate — this is a platform-wide event
# 2. Trigger emergency key rotation
python scripts/rotate-jwks.py --emergency
# 3. Revoke all active sessions and outstanding tokens
python scripts/revoke-client.py --all --reason "key-compromise"
# 4. Notify security@journeyoflife.org with full timeline
# 5. Document in jol-compliance incident register
```

***

## License

Proprietary — All Rights Reserved. See [`LICENSE`](LICENSE).
