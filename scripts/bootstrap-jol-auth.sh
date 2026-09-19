#!/bin/bash
# ============================================================================
# JOL Platform — Complete PostgreSQL Cluster Bootstrap
# ============================================================================
# Creates ALL databases, roles, and extensions for the JOL platform,
# then runs Alembic migrations and starts the jol-auth server.
#
# Architecture (SOC 2 / GDPR / ISO 27001 compliant):
#
#   jol_platform_control   →  jol_control_user     (Control Plane)
#   jol_identity           →  jol_identity_user     (Identity & Access)
#   jol_audit              →  jol_audit_user        (Immutable Audit Trail)
#   jol_ai_platform        →  jol_ai_user           (AI Agents & LLM)
#   jol_media_storage      →  jol_media_user        (Media Metadata)
#   jol_lt_platform_prod   →  jol_lt_app_user       (Lithuania Pilot)
#
# Multi-tenancy: tenant_id + organization_id + PostgreSQL RLS
# Audit: append-only, immutable records
# GDPR: deleted_at, anonymized_at, consent_version, retention_policy
#
# Usage:  sudo bash /opt/jol/repos/jol-auth/scripts/bootstrap-jol-auth.sh
# ============================================================================

set -euo pipefail

# --- Config ---
PROJECT_DIR="/opt/jol/repos/jol-auth"
VENV_DIR="${PROJECT_DIR}/.venv"
REAL_USER="${SUDO_USER:-$USER}"
PG_VERSION="16"
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"
PG_HBA_BACKUP="/tmp/pg_hba.conf.backup.$(date +%s)"
SQL_TMP="/tmp/jol_create_dbs.sql"

echo "================================================"
echo "  JOL Platform — Complete Bootstrap"
echo "  Running as: $(whoami) (real user: ${REAL_USER})"
echo "================================================"
echo ""

# ============================================================================
# STEP 1: Create ALL PostgreSQL databases + users
# ============================================================================
echo "[1/4] Creating PostgreSQL databases..."
echo ""

# --- Temporarily allow trust auth for local connections ---
if [ -f "${PG_HBA}" ]; then
    echo "  → Temporarily enabling trust auth..."
    cp "${PG_HBA}" "${PG_HBA_BACKUP}"
    sed -i '1ilocal all all trust' "${PG_HBA}"
    sed -i '1ihost all all 127.0.0.1/32 trust' "${PG_HBA}"
    sed -i '1ihost all all ::1/128 trust' "${PG_HBA}"
    pg_ctlcluster ${PG_VERSION} main reload 2>/dev/null || systemctl reload postgresql 2>/dev/null || true
fi

restore_pg_hba() {
    if [ -f "${PG_HBA_BACKUP}" ]; then
        cp "${PG_HBA_BACKUP}" "${PG_HBA}"
        rm -f "${PG_HBA_BACKUP}"
        pg_ctlcluster ${PG_VERSION} main reload 2>/dev/null || systemctl reload postgresql 2>/dev/null || true
        echo "  → pg_hba.conf restored."
    fi
}
trap restore_pg_hba EXIT

# --- Write all SQL to a temp file (more reliable than heredoc with su) ---
cat > "${SQL_TMP}" << 'SQLEOF'
-- ============================================================
-- Helper: create role if not exists, else reset password
-- ============================================================
CREATE OR REPLACE FUNCTION _create_or_reset_role(p_name TEXT, p_pass TEXT)
RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = p_name) THEN
        EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', p_name, p_pass);
        RAISE NOTICE 'Created role %', p_name;
    ELSE
        EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', p_name, p_pass);
        RAISE NOTICE 'Updated password for %', p_name;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- 1. jol_platform_control → jol_control_user
-- ============================================================
SELECT _create_or_reset_role('jol_control_user', '${JOL_CONTROL_DB_PASSWORD}');
SELECT 'CREATE DATABASE jol_platform_control OWNER jol_control_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_platform_control')\gexec
GRANT ALL PRIVILEGES ON DATABASE jol_platform_control TO jol_control_user;

-- ============================================================
-- 2. jol_identity → jol_identity_user
-- ============================================================
SELECT _create_or_reset_role('jol_identity_user', '${JOL_IDENTITY_DB_PASSWORD}');
SELECT 'CREATE DATABASE jol_identity OWNER jol_identity_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_identity')\gexec
GRANT ALL PRIVILEGES ON DATABASE jol_identity TO jol_identity_user;

-- ============================================================
-- 3. jol_audit → jol_audit_user (append-only, immutable)
-- ============================================================
SELECT _create_or_reset_role('jol_audit_user', '${JOL_AUDIT_DB_PASSWORD}');
SELECT 'CREATE DATABASE jol_audit OWNER jol_audit_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_audit')\gexec
GRANT ALL PRIVILEGES ON DATABASE jol_audit TO jol_audit_user;

-- ============================================================
-- 4. jol_ai_platform → jol_ai_user
-- ============================================================
SELECT _create_or_reset_role('jol_ai_user', '${JOL_AI_DB_PASSWORD}');
SELECT 'CREATE DATABASE jol_ai_platform OWNER jol_ai_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_ai_platform')\gexec
GRANT ALL PRIVILEGES ON DATABASE jol_ai_platform TO jol_ai_user;

-- ============================================================
-- 5. jol_media_storage → jol_media_user
-- ============================================================
SELECT _create_or_reset_role('jol_media_user', '${JOL_MEDIA_DB_PASSWORD}');
SELECT 'CREATE DATABASE jol_media_storage OWNER jol_media_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_media_storage')\gexec
GRANT ALL PRIVILEGES ON DATABASE jol_media_storage TO jol_media_user;

-- ============================================================
-- 6. jol_lt_platform_prod → jol_lt_app_user
-- ============================================================
SELECT _create_or_reset_role('jol_lt_app_user', '${JOL_LT_DB_PASSWORD}');
SELECT 'CREATE DATABASE jol_lt_platform_prod OWNER jol_lt_app_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_lt_platform_prod')\gexec
GRANT ALL PRIVILEGES ON DATABASE jol_lt_platform_prod TO jol_lt_app_user;

-- Cleanup helper function
DROP FUNCTION _create_or_reset_role(TEXT, TEXT);
SQLEOF

# Execute the SQL as postgres user
su - postgres -c "psql -f ${SQL_TMP}"
rm -f "${SQL_TMP}"

# --- Enable extensions on all databases ---
echo ""
echo "  → Enabling extensions on all databases..."

for db_info in \
    "jol_platform_control:jol_control_user" \
    "jol_identity:jol_identity_user" \
    "jol_audit:jol_audit_user" \
    "jol_ai_platform:jol_ai_user" \
    "jol_media_storage:jol_media_user" \
    "jol_lt_platform_prod:jol_lt_app_user"
do
    db_name="${db_info%%:*}"
    db_user="${db_info##*:}"
    su - postgres -c "psql -d ${db_name}" << EOF
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL ON SCHEMA public TO ${db_user};
EOF
    echo "    ✓ ${db_name}"
done

# Restore pg_hba.conf
restore_pg_hba
trap '' EXIT

echo ""
echo "  All databases created successfully."
echo ""

# --- Verify connections ---
# Check if all database passwords are set
for var in JOL_CONTROL_DB_PASSWORD JOL_IDENTITY_DB_PASSWORD JOL_AUDIT_DB_PASSWORD JOL_AI_DB_PASSWORD JOL_MEDIA_DB_PASSWORD JOL_LT_DB_PASSWORD; do
    if [ -z "${!var}" ]; then
        echo "    ✗ $var not set"
        echo "    → Run: source scripts/run-with-vault.sh"
        exit 1
    fi
done

echo "  → Verifying connections..."
for db_info in \
    "jol_identity:${JOL_IDENTITY_DB_PASSWORD}:jol_identity_user" \
    "jol_lt_platform_prod:${JOL_LT_DB_PASSWORD}:jol_lt_app_user"
do
    db_name="${db_info%%:*}"
    rest="${db_info#*:}"
    db_pass="${rest%%:*}"
    db_user="${rest##*:}"
    if su - "${REAL_USER}" -c "PGPASSWORD='${db_pass}' psql -h localhost -U '${db_user}' -d '${db_name}' -c 'SELECT 1;'" > /dev/null 2>&1; then
        echo "    ✓ ${db_name} — connection OK"
    else
        echo "    ✗ ${db_name} — connection FAILED"
    fi
done
echo ""

# ============================================================================
# STEP 2: Run Alembic migrations (as the real user)
# ============================================================================
echo "[2/4] Running Alembic migrations on jol_identity..."
echo ""

su - "${REAL_USER}" -c "bash -c '
    set -e
    cd \"${PROJECT_DIR}\"
    source \"${VENV_DIR}/bin/activate\"
    echo \"  Python: \$(python --version)\"
    echo \"  Venv:   \$(which python)\"
    echo \"\"
    alembic upgrade head
    echo \"\"
    echo \"  Migrations complete.\"
'"
echo ""

# ============================================================================
# STEP 3: Verify migration tables
# ============================================================================
echo "[3/4] Verifying database schema..."
su - "${REAL_USER}" -c "PGPASSWORD='${JOL_IDENTITY_DB_PASSWORD}' psql -h localhost -U jol_identity_user -d jol_identity -c \"\\dt\"" 2>&1 || echo "  (Could not list tables — check migrations)"
echo ""

# ============================================================================
# STEP 4: Start the FastAPI server
# ============================================================================
echo "[4/4] Starting jol-auth server..."
echo ""
echo "  Server:   http://localhost:8000"
echo "  Health:   curl http://localhost:8000/api/health"
echo "  OIDC:     curl http://localhost:8000/.well-known/openid-configuration"
echo ""
echo "  Press Ctrl+C to stop."
echo ""
echo "================================================"
echo ""

su - "${REAL_USER}" -c "bash -c '
    cd \"${PROJECT_DIR}\"
    source \"${VENV_DIR}/bin/activate\"
    python -m app.main
'"
