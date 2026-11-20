# Key Rotation

## Overview

JWKS key rotation ensures that signing keys are periodically replaced to limit the blast radius of a key compromise.

## Rotation Strategy

1. **Generate** a new RSA key pair and assign a new `kid`
2. **Publish** the new public key alongside the existing one in the JWKS document
3. **Sign** new tokens with the new private key
4. **Verify** incoming tokens against all published public keys
5. **Retire** the old key after all unexpired tokens have been replaced (max access_token_ttl + refresh_token_ttl)

## Rotation Schedule

| Key Type | Rotation Interval | Overlap Period |
|---|---|---|
| JWT Signing Key | 90 days | 30 days (max token lifetime) |
| Client Secrets | On demand (revocation) | N/A |
| TOTP Secrets | Per-user, on re-enrolment | N/A |

## Runbook

1. Execute `scripts/rotate-jwks.py`
2. Verify new `kid` appears at `/api/jwks/`
3. Confirm new tokens are signed with the new `kid`
4. Schedule old key removal after overlap period
5. Emit audit event for the rotation

## Emergency Rotation

If a key is suspected compromised:
1. Immediately rotate using `scripts/rotate-jwks.py --emergency`
2. Revoke all existing tokens via `RevocationService.revoke_tenant()`
3. Notify affected clients
4. File a security incident per SECURITY.md
