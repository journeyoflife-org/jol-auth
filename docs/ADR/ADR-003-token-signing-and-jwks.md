# ADR-003: Token Signing and JWKS Strategy

## Status
Proposed

## Context
Tokens must be signed with an asymmetric algorithm so that resource servers can verify them without accessing the private key.

## Decision
- Algorithm: RS256 (RSA + SHA-256)
- Key size: 2048-bit RSA keys (minimum)
- JWKS endpoint serves the public key set at `/api/jwks/`
- Key rotation every 90 days with a 30-day overlap period
- Private keys are loaded from a vault (never stored in source control)
- Each key has a unique `kid` (Key ID) included in the JWT header

## Consequences
- Resource servers must fetch and cache the JWKS document
- During rotation, both old and new public keys are published
- Emergency rotation procedure exists in docs/key-rotation.md
