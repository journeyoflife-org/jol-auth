#!/bin/bash
# ============================================================================
# Reset ALL database passwords + run migrations + start server
# ============================================================================
# Fixes: wrong password for jol_identity_user (or any other user)
#
# Usage:  sudo bash /opt/jol/repos/jol-auth/scripts/fix-and-run.sh
# ============================================================================

set -euo pipefail

PROJECT_DIR="/opt/jol/repos/jol-auth"
VENV_DIR="${PROJECT_DIR}/.venv"
REAL_USER="${SUDO_USER:-$USER}"
PG_HBA="/etc/postgresql/16/main/pg_hba.conf"
PG_HBA_BAK="/tmp/pg_hba.conf.bak.$(date +%s)"

echo "================================================"
echo "  JOL Platform — Fix Passwords & Run"
echo "  Real user: ${REAL_USER}"
echo "================================================"
echo ""

# ============================================================
# STEP 1: Temporarily enable trust auth
# ============================================================
echo "[1/3] Resetting all database passwords..."
echo ""

cp "${PG_HBA}" "${PG_HBA_BAK}"
sed -i '1ilocal all all trust' "${PG_HBA}"
sed -i '1ihost all all 127.0.0.1/32 trust' "${PG_HBA}"
sed -i '1ihost all all ::1/128 trust' "${PG_HBA}"
pg_ctlcluster 16 main reload 2>/dev/null || true
echo "  → Trust auth enabled temporarily"

# ============================================================
# STEP 2: Reset ALL passwords + ensure databases exist
# ============================================================

# Write SQL to temp file
cat > /tmp/jol_reset.sql << 'SQLEOF'
-- Reset ALL passwords to known-good values
ALTER ROLE jol_control_user   WITH LOGIN PASSWORD '${JOL_CONTROL_DB_PASSWORD}';
ALTER ROLE jol_identity_user  WITH LOGIN PASSWORD '${JOL_IDENTITY_DB_PASSWORD}';
ALTER ROLE jol_audit_user     WITH LOGIN PASSWORD '${JOL_AUDIT_DB_PASSWORD}';
ALTER ROLE jol_ai_user        WITH LOGIN PASSWORD '${JOL_AI_DB_PASSWORD}';
ALTER ROLE jol_media_user     WITH LOGIN PASSWORD '${JOL_MEDIA_DB_PASSWORD}';
ALTER ROLE jol_lt_app_user    WITH LOGIN PASSWORD '${JOL_LT_DB_PASSWORD}';

-- Show all roles for verification
SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname LIKE 'jol_%' ORDER BY rolname;
SQLEOF

# Run as postgres user (runuser is more reliable than su on Ubuntu)
runuser -u postgres -- psql -f /tmp/jol_reset.sql
rm -f /tmp/jol_reset.sql

# Restore pg_hba.conf
cp "${PG_HBA_BAK}" "${PG_HBA}"
rm -f "${PG_HBA_BAK}"
pg_ctlcluster 16 main reload 2>/dev/null || true
echo "  → pg_hba.conf restored"

echo ""

# Verify jol_identity connection
echo "  → Verifying jol_identity connection..."
if runuser -u "${REAL_USER}" -- env PGPASSWORD='${JOL_IDENTITY_DB_PASSWORD}' psql -h localhost -U jol_identity_user -d jol_identity -c "SELECT current_user, current_database();" 2>&1; then
    echo "  → Connection OK!"
else
    echo "  → FAILED — the jol_identity database may not exist yet."
    echo "  → Creating it now..."

    # Re-enable trust auth temporarily
    cp "${PG_HBA}" "${PG_HBA_BAK}"
    sed -i '1ilocal all all trust' "${PG_HBA}"
    pg_ctlcluster 16 main reload 2>/dev/null || true

    runuser -u postgres -- psql << 'SQL'
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jol_identity_user') THEN
        CREATE ROLE jol_identity_user WITH LOGIN PASSWORD '${JOL_IDENTITY_DB_PASSWORD}';
    ELSE
        ALTER ROLE jol_identity_user WITH LOGIN PASSWORD '${JOL_IDENTITY_DB_PASSWORD}';
    END IF;
END $$;

SELECT 'CREATE DATABASE jol_identity OWNER jol_identity_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'jol_identity')\gexec

GRANT ALL PRIVILEGES ON DATABASE jol_identity TO jol_identity_user;
SQL

    runuser -u postgres -- psql -d jol_identity << 'SQL'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL ON SCHEMA public TO jol_identity_user;
SQL

    # Restore pg_hba.conf
    cp "${PG_HBA_BAK}" "${PG_HBA}"
    rm -f "${PG_HBA_BAK}"
    pg_ctlcluster 16 main reload 2>/dev/null || true
    echo "  → jol_identity database created."
fi

echo ""

# ============================================================
# STEP 3: Run Alembic migrations + start server
# ============================================================
echo "[2/3] Running Alembic migrations..."
echo ""

runuser -u "${REAL_USER}" -- bash -c "
    set -e
    cd '${PROJECT_DIR}'
    source '${VENV_DIR}/bin/activate'
    echo '  Python: \$(python --version)'
    echo '  Venv:   \$(which python)'
    echo ''
    alembic upgrade head
    echo ''
    echo '  ✓ Migrations complete'
    echo ''
    echo '[3/3] Starting jol-auth server...'
    echo '  Server: http://localhost:8000'
    echo '  Health: curl http://localhost:8000/api/health'
    echo '  OIDC:   curl http://localhost:8000/.well-known/openid-configuration'
    echo ''
    python -m app.main
"
