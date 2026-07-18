# Architecture

## Platform Overview

The Journey of Life (JOL) platform serves approximately 400,000 religious institution websites across 27 European Union member states. The architecture is designed for multi-tenant isolation, regulatory compliance, and horizontal scalability.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Edge / CDN                               │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────┐
│                    API Gateway / Load Balancer                    │
│              (TLS termination, rate limiting, routing)            │
└────────────────────────┬─────────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
┌─────────▼──┐  ┌───────▼───┐  ┌───────▼───┐
│  Tenant    │  │  Tenant   │  │  Tenant   │
│  Service   │  │  Service  │  │  Service  │
│  (EU-West) │  │  (EU-Cen) │  │  (EU-East)│
└─────┬──────┘  └─────┬─────┘  └─────┬─────┘
      │               │               │
┌─────▼───────────────▼───────────────▼─────┐
│            Shared Services Layer           │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │  Auth /  │ │  Audit   │ │  Config   │  │
│  │  IAM     │ │  Logging │ │  Service  │  │
│  └──────────┘ └──────────┘ └───────────┘  │
└──────────────────┬────────────────────────┘
                   │
┌──────────────────▼────────────────────────┐
│              Data Layer                    │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │ Tenant   │ │ Object   │ │  Cache    │  │
│  │ Databases│ │ Storage  │ │  (Redis)  │  │
│  │ (per-    │ │ (S3-com- │ │           │  │
│  │  region) │ │  patible)│ │           │  │
│  └──────────┘ └──────────┘ └───────────┘  │
└───────────────────────────────────────────┘
```

## Design Principles

| Principle                  | Application                                                                |
|----------------------------|----------------------------------------------------------------------------|
| Multi-tenant isolation     | Each institution's data is logically isolated; no cross-tenant queries.    |
| Data residency             | Tenant data is stored within the EU region of the subscribing institution. |
| Defence in depth           | Multiple security layers; no single point of trust.                        |
| Least privilege            | Services and personnel operate with the minimum permissions required.      |
| Observability              | Structured logging, distributed tracing, and metric collection by default. |
| Fail-safe defaults         | New tenants inherit the most restrictive configuration.                    |

## Technology Standards

| Layer            | Standard                                             |
|------------------|------------------------------------------------------|
| Language         | Python 3.12+                                         |
| API              | REST (OpenAPI 3.1); gRPC for internal service calls  |
| Authentication   | OAuth 2.0 / OpenID Connect                           |
| Data storage     | PostgreSQL 16+; S3-compatible object storage          |
| Caching          | Redis 7+                                             |
| CI/CD            | GitHub Actions                                       |
| Static analysis  | CodeQL, Qodana, Ruff                                 |
| Containerisation | Docker; Kubernetes for orchestration                 |

## Deployment Topology

- **Regions**: Three EU deployment regions (West, Central, East) for latency optimisation and data residency.
- **Environments**: `development` → `staging` → `production`.
- **Promotion**: Artefacts are immutable; environment promotion is via configuration change, not rebuild.

## Security Architecture

- **Network**: All inter-service communication is encrypted (mTLS within the cluster).
- **Identity**: Service accounts follow the principle of least privilege with short-lived credentials.
- **Secrets**: Managed via a vault service; never stored in source control or environment files.
- **Audit**: All write operations emit audit events to an append-only log.
- **Scanning**: CodeQL and secret scanning run on every pull request and on a weekly schedule.

## Data Protection Architecture

- **Personal data**: Classified at the field level; processing requires a lawful basis record.
- **Encryption at rest**: All persistent storage is encrypted using AES-256.
- **Encryption in transit**: TLS 1.3 enforced for all external and internal endpoints.
- **Retention**: Automated retention policies with configurable per-tenant schedules.
- **DPIA**: Required before any new personal data processing is introduced (see `docs/DPIA-template.md`).
