# Authentication Flows

## Supported Flows

### 1. Authorization Code (with PKCE)
```
Client → /api/oauth/authorize → Login/Consent → Redirect with code
Client → /api/oauth/token (code + code_verifier) → access_token + refresh_token + id_token
```

### 2. Client Credentials
```
Service → /api/oauth/token (client_id + client_secret) → access_token
```

### 3. Refresh Token Rotation
```
Client → /api/oauth/token (grant_type=refresh_token) → new access_token + new refresh_token
Old refresh token is revoked. Reuse of revoked token revokes the entire token family.
```

### 4. Token Revocation (RFC 7009)
```
Client → /api/oauth/revoke → 200 OK (even if token was already revoked)
```

### 5. Token Introspection (RFC 7662)
```
Resource Server → /api/oauth/introspect → {active: true/false, ...}
```

## Flow Diagrams

### Authorization Code + PKCE
```
┌────────┐                    ┌──────────┐                  ┌──────────┐
│ Client │                    │  Auth    │                  │  Resource│
│        │──authorize+PKCE───→│  Server  │                  │  Server  │
│        │←──code─────────────│          │                  │          │
│        │──code+verifier────→│          │                  │          │
│        │←──tokens───────────│          │                  │          │
│        │────access_token──────────────────────────────────→│          │
│        │←──resource response───────────────────────────────│          │
└────────┘                    └──────────┘                  └──────────┘
```
