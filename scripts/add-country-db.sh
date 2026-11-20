#!/bin/bash
# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# ============================================================================
# Add a new country database to the JOL PostgreSQL cluster
# ============================================================================
# Usage:
#   sudo bash scripts/add-country-db.sh <country_code> [country_name]
#
# Examples:
#   sudo bash scripts/add-country-db.sh lv  "Latvia"
#   sudo bash scripts/add-country-db.sh ee  "Estonia"
#   sudo bash scripts/add-country-db.sh de  "Germany"
#
# Creates:
#   - Role:     jol_<code>_app_user
#   - Password: jol_<code>_app_pass
#   - Database: jol_<code>  (cloned from jol_template)
# ============================================================================

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: sudo bash $0 <country_code> [country_name]"
    echo "  e.g. sudo bash $0 lv Latvia"
    exit 1
fi

CODE="$1"
NAME="${2:-$CODE}"
DB_USER="jol_${CODE}_app_user"
DB_PASS="jol_${CODE}_app_pass"
DB_NAME="jol_${CODE}"

echo "================================================"
echo "  Adding Country Database"
echo "  Code:     ${CODE}"
echo "  Name:     ${NAME}"
echo "  Database: ${DB_NAME}"
echo "  Role:     ${DB_USER}"
echo "================================================"

# Create role
echo "  → Creating role ${DB_USER}..."
sudo -u postgres psql << SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Created role ${DB_USER}';
    ELSE
        ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Updated password for ${DB_USER}';
    END IF;
END
\$\$;
SQL

# Create database from template
echo "  → Creating database ${DB_NAME} from jol_template..."
sudo -u postgres psql << SQL
SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER} TEMPLATE jol_template'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}')\gexec
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL

# Grant schema privileges
echo "  → Granting schema privileges..."
sudo -u postgres psql -d "${DB_NAME}" << SQL
GRANT ALL ON SCHEMA public TO ${DB_USER};
SQL

echo ""
echo "================================================"
echo "  Done!"
echo "================================================"
echo ""
echo "  Test connection:"
echo "    PGPASSWORD=${DB_PASS} psql -h localhost -U ${DB_USER} -d ${DB_NAME} -c 'SELECT 1;'"
echo ""
