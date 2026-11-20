# Secret Management

## Overview

This document describes how secrets are managed across development, staging,
and production environments for jol-auth. The golden rule is:

> **No secrets in source code, Dockerfiles, or docker-compose files.**

## Secret Inventory

| Secret | Purpose | Rotation Period |
|--------|---------|-----------------|
| `APP_SECRET_KEY` | Session signing, CSRF tokens | 90 days |
| `MFA_ENCRYPTION_KEY` | AES-256-GCM encryption of TOTP secrets | 180 days |
| `DATABASE_URL` (password component) | PostgreSQL connection | 90 days |
| `POSTGRES_PASSWORD` | PostgreSQL superuser-equivalent | 90 days |
| `REDIS_PASSWORD` | Redis authentication | 90 days |
| `JWKS_PRIVATE_KEY_PATH` | JWT signing private key (RS256) | 365 days |
| Client secrets | OAuth client authentication | On compromise |

## Environment-Specific Strategies

### Development

Secrets are stored in `.env` (gitignored). Use `.env.example` as a template:

```bash
cp .env.example .env
# Edit .env and generate required keys:
python -c "import secrets; print(secrets.token_urlsafe(48))"  # APP_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # MFA_ENCRYPTION_KEY
```

### Docker (Swarm)

Docker Secrets mount sensitive values as files under `/run/secrets/`:

```bash
# Create secrets
echo "your_db_password" | docker secret create jol_db_password -
echo "your_app_secret"  | docker secret create jol_app_secret -
echo "your_mfa_key"     | docker secret create jol_mfa_encryption_key -

# Deploy
docker stack deploy -c docker-compose.prod.yml jol-auth
```

The application reads secrets from `MFA_ENCRYPTION_KEY_FILE` environment
variable, which points to the mounted file path.

### Kubernetes

Use Kubernetes Secrets with `secretKeyRef`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jol-auth-secrets
type: Opaque
stringData:
  app_secret_key: "..."
  mfa_encryption_key: "..."
  database_url: "..."
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: jol-auth
          envFrom:
            - secretRef:
                name: jol-auth-secrets
```

For enhanced security, use the **Sealed Secrets** controller or
**External Secrets Operator** backed by AWS KMS / GCP KMS / Vault.

### HashiCorp Vault (Production)

Use the Vault Agent Sidecar Injector to inject secrets at runtime:

```yaml
# Vault Kubernetes annotation
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/agent-inject-secret-mfa-key: "secret/data/jol-auth/mfa-encryption-key"
vault.hashicorp.com/agent-inject-template-mfa-key: |
  {{- with secret "secret/data/jol-auth/mfa-encryption-key" -}}
  export MFA_ENCRYPTION_KEY="{{ .Data.data.key }}"
  {{- end }}
```

## MFA Encryption Key Rotation

The MFA encryption key is used to encrypt TOTP secrets at rest. Rotation
requires re-encrypting all stored secrets:

1. Generate a new Fernet key:
   ```python
   from cryptography.fernet import Fernet

   new_key = Fernet.generate_key().decode()
   ```

2. Run the key rotation script:
   ```bash
   # Set both old and new keys
   export MFA_ENCRYPTION_KEY_OLD=<old_key>
   export MFA_ENCRYPTION_KEY=<new_key>

   # Run rotation
   python scripts/rotate-mfa-key.py
   ```

3. Update the secret in Docker/K8s/Vault with the new key.

4. Verify by testing MFA login for a sample user.

## JWT Signing Key Rotation

JWT signing keys (RS256) are managed by the KeyManager:

1. Generate a new key pair:
   ```bash
   python scripts/rotate-jwks.py
   ```

2. The old key remains valid during the overlap window (configurable).
3. Old key is automatically retired after the overlap period expires.

## Database Password Rotation

1. Create a new database role with a new password.
2. Update the application secret (Docker/K8s/Vault).
3. Rolling restart the application pods.
4. Verify all pods are using the new connection string.
5. Revoke the old role's permissions.

## Break-Glass Procedure

For emergency access to encrypted secrets:

1. The MFA encryption key should be stored in a sealed envelope in a
   physical safe (offline backup).
2. Access requires two-person authorization (SOC 2 CC6.1).
3. All break-glass access must be logged and reviewed within 24 hours.

## Audit Requirements

- All secret accesses must be logged.
- Secret rotation events must trigger an audit event.
- Break-glass access triggers a P1 alert for security review.
- SOC 2 requires evidence of rotation every 90 days for critical secrets.
