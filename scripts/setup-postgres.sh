#!/bin/bash
# Set up PostgreSQL user 'jol_identity_user' and database 'jol_identity' for jol-auth.
# Run with:  sudo bash scripts/setup-postgres.sh
set -euo pipefail

DB_USER="jol_identity_user"
DB_PASS="${JOL_IDENTITY_DB_PASSWORD}"
DB_NAME="jol_identity"

echo "==> Setting up PostgreSQL for jol-auth (Identity & Access)..."

sudo -u postgres psql << SQL
-- Create role if it doesn't exist, or set password if it does
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Created user ${DB_USER}';
    ELSE
        ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Reset password for user ${DB_USER}';
    END IF;
END
\$\$;

-- Create database if it doesn't exist
SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};

-- Enable UUID extension (needed by the app)
\c ${DB_NAME}
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL ON SCHEMA public TO ${DB_USER};

RAISE NOTICE 'Setup complete.';
SQL

echo "==> PostgreSQL setup complete."
echo "    User: ${DB_USER}"
echo "    Database: ${DB_NAME}"
echo ""
echo "Test the connection:"
echo "  PGPASSWORD=${DB_PASS} psql -h localhost -U ${DB_USER} -d ${DB_NAME} -c 'SELECT 1;'"
