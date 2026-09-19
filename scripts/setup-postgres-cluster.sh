#!/bin/bash
# ============================================================================
# PostgreSQL Cluster Setup — JOL Platform
# ============================================================================
# Architecture (SOC 2 / GDPR / ISO 27001 compliant):
#
#   jol_platform_control   →  jol_control_user      (Control Plane)
#   jol_identity           →  jol_identity_user      (Identity & Access)
#   jol_audit              →  jol_audit_user         (Immutable Audit Trail)
#   jol_ai_platform        →  jol_ai_user            (AI Agents & LLM)
#   jol_media_storage      →  jol_media_user         (Media Metadata)
#   jol_lt_platform_prod   →  jol_lt_app_user        (Lithuania Pilot)
#
# Multi-tenancy: tenant_id + organization_id + PostgreSQL RLS
# Audit: append-only, immutable records
# GDPR: deleted_at, anonymized_at, consent_version, retention_policy
#
# Usage:  sudo bash scripts/setup-postgres-cluster.sh
# Idempotent: safe to run multiple times.
# ============================================================================

set -euo pipefail

echo "================================================"
echo "  JOL PostgreSQL Cluster Setup"
echo "================================================"

create_role() {
    local role_name="$1" role_pass="$2"
    echo "  → Role: ${role_name}"
    sudo -u postgres psql << SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role_name}') THEN
        CREATE ROLE ${role_name} WITH LOGIN PASSWORD '${role_pass}';
        RAISE NOTICE 'Created role ${role_name}';
    ELSE
        ALTER ROLE ${role_name} WITH LOGIN PASSWORD '${role_pass}';
        RAISE NOTICE 'Updated password for ${role_name}';
    END IF;
END
\$\$;
SQL
}

create_db() {
    local db_name="$1" db_owner="$2"
    echo "  → Database: ${db_name} (owner: ${db_owner})"
    sudo -u postgres psql << SQL
SELECT 'CREATE DATABASE ${db_name} OWNER ${db_owner}'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${db_name}')\gexec
GRANT ALL PRIVILEGES ON DATABASE ${db_name} TO ${db_owner};
SQL
}

setup_db() {
    local db_name="$1" db_user="$2"
    echo "  → Extensions: ${db_name}"
    sudo -u postgres psql -d "${db_name}" << SQL
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL ON SCHEMA public TO ${db_user};
SQL
}

# ============================================================
# 1. Platform Control Plane
# ============================================================
echo ""
echo "[1/6] Platform Control Plane"
echo "      jol_platform_control → jol_control_user"
create_role "jol_control_user" "${JOL_CONTROL_DB_PASSWORD}"
create_db    "jol_platform_control" "jol_control_user"
setup_db     "jol_platform_control" "jol_control_user"

# ============================================================
# 2. Identity & Access
# ============================================================
echo ""
echo "[2/6] Identity & Access"
echo "      jol_identity → jol_identity_user"
create_role "jol_identity_user" "${JOL_IDENTITY_DB_PASSWORD}"
create_db    "jol_identity" "jol_identity_user"
setup_db     "jol_identity" "jol_identity_user"

# ============================================================
# 3. Audit (append-only, immutable)
# ============================================================
echo ""
echo "[3/6] Audit Trail (SOC 2 / ISO 27001)"
echo "      jol_audit → jol_audit_user"
create_role "jol_audit_user" "${JOL_AUDIT_DB_PASSWORD}"
create_db    "jol_audit" "jol_audit_user"
setup_db     "jol_audit" "jol_audit_user"

# ============================================================
# 4. AI Platform
# ============================================================
echo ""
echo "[4/6] AI Platform"
echo "      jol_ai_platform → jol_ai_user"
create_role "jol_ai_user" "${JOL_AI_DB_PASSWORD}"
create_db    "jol_ai_platform" "jol_ai_user"
setup_db     "jol_ai_platform" "jol_ai_user"

# ============================================================
# 5. Media Storage (metadata only — files in MinIO/S3)
# ============================================================
echo ""
echo "[5/6] Media Storage"
echo "      jol_media_storage → jol_media_user"
create_role "jol_media_user" "${JOL_MEDIA_DB_PASSWORD}"
create_db    "jol_media_storage" "jol_media_user"
setup_db     "jol_media_storage" "jol_media_user"

# ============================================================
# 6. Lithuania Pilot (Production)
# ============================================================
echo ""
echo "[6/6] Lithuania Pilot — Production"
echo "      jol_lt_platform_prod → jol_lt_app_user"
create_role "jol_lt_app_user" "${JOL_LT_DB_PASSWORD}"
create_db    "jol_lt_platform_prod" "jol_lt_app_user"
setup_db     "jol_lt_platform_prod" "jol_lt_app_user"

# ============================================================
# Summary
# ============================================================
echo ""
echo "================================================"
echo "  Cluster Setup Complete"
echo "================================================"
echo ""
echo "  Databases:"
echo "    jol_platform_control   →  jol_control_user"
echo "    jol_identity           →  jol_identity_user"
echo "    jol_audit              →  jol_audit_user"
echo "    jol_ai_platform        →  jol_ai_user"
echo "    jol_media_storage      →  jol_media_user"
echo "    jol_lt_platform_prod   →  jol_lt_app_user"
echo ""
echo "  Test connections:"
echo "    PGPASSWORD=${JOL_CONTROL_DB_PASSWORD}   psql -h localhost -U jol_control_user -d jol_platform_control -c 'SELECT 1;'"
echo "    PGPASSWORD=${JOL_IDENTITY_DB_PASSWORD} psql -h localhost -U jol_identity_user -d jol_identity -c 'SELECT 1;'"
echo "    PGPASSWORD=${JOL_AUDIT_DB_PASSWORD}    psql -h localhost -U jol_audit_user -d jol_audit -c 'SELECT 1;'"
echo "    PGPASSWORD=${JOL_AI_DB_PASSWORD}       psql -h localhost -U jol_ai_user -d jol_ai_platform -c 'SELECT 1;'"
echo "    PGPASSWORD=${JOL_MEDIA_DB_PASSWORD}     psql -h localhost -U jol_media_user -d jol_media_storage -c 'SELECT 1;'"
echo "    PGPASSWORD=JOL_LT_User_2026_pAWvefHijaathQ9C psql -h localhost -U jol_lt_app_user -d jol_lt_platform_prod -c 'SELECT 1;'"
echo ""
