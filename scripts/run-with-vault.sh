#!/bin/bash
# ============================================================================
# run-with-vault.sh — Load database passwords from Ansible Vault
# ============================================================================
# Usage: source scripts/run-with-vault.sh && ./scripts/bootstrap-jol-auth.sh
#
# This script loads database passwords from the Ansible Vault and exports
# them as environment variables. The bootstrap scripts then use these
# environment variables instead of hardcoded passwords.
#
# Prerequisites:
#   - ansible-vault must be installed
#   - ansible/group_vars/jol_auth/vault.yml must exist and be encrypted
#   - You must know the vault password
#
# Security:
#   - Passwords are loaded into memory only (not written to disk)
#   - Environment variables are cleared when the shell exits
#   - Never commit this script with real passwords
# ============================================================================

set -e

VAULT_FILE="ansible/group_vars/jol_auth/vault.yml"

# Check if vault file exists
if [ ! -f "$VAULT_FILE" ]; then
    echo "✗ Vault file not found: $VAULT_FILE"
    echo "→ Create it with: ansible-vault create $VAULT_FILE"
    return 1 2>/dev/null || exit 1
fi

# Check if ansible-vault is installed
if ! command -v ansible-vault &> /dev/null; then
    echo "✗ ansible-vault not found"
    echo "→ Install with: pip install ansible"
    return 1 2>/dev/null || exit 1
fi

echo "Loading database passwords from Ansible Vault..."

# Decrypt vault and extract passwords
export JOL_CONTROL_DB_PASSWORD=$(ansible-vault view "$VAULT_FILE" | grep vault_jol_control_db_password | cut -d'"' -f2)
export JOL_IDENTITY_DB_PASSWORD=$(ansible-vault view "$VAULT_FILE" | grep vault_jol_identity_db_password | cut -d'"' -f2)
export JOL_AUDIT_DB_PASSWORD=$(ansible-vault view "$VAULT_FILE" | grep vault_jol_audit_db_password | cut -d'"' -f2)
export JOL_AI_DB_PASSWORD=$(ansible-vault view "$VAULT_FILE" | grep vault_jol_ai_db_password | cut -d'"' -f2)
export JOL_MEDIA_DB_PASSWORD=$(ansible-vault view "$VAULT_FILE" | grep vault_jol_media_db_password | cut -d'"' -f2)
export JOL_LT_DB_PASSWORD=$(ansible-vault view "$VAULT_FILE" | grep vault_jol_lt_db_password | cut -d'"' -f2)

# Verify passwords were loaded
PASSWORDS_OK=true

for var in JOL_CONTROL_DB_PASSWORD JOL_IDENTITY_DB_PASSWORD JOL_AUDIT_DB_PASSWORD JOL_AI_DB_PASSWORD JOL_MEDIA_DB_PASSWORD JOL_LT_DB_PASSWORD; do
    val=$(eval echo \$$var)
    if [ -z "$val" ] || [ "$val" = "PLACEHOLDER_GENERATE_NEW_PASSWORD" ]; then
        echo "✗ $var not set or is placeholder"
        PASSWORDS_OK=false
    fi
done

if [ "$PASSWORDS_OK" = false ]; then
    echo "→ Update vault file with real passwords and encrypt"
    return 1 2>/dev/null || exit 1
fi

echo "✓ All 6 database passwords loaded successfully"
echo ""
echo "You can now run the bootstrap script:"
echo "  ./scripts/bootstrap-jol-auth.sh"
echo ""
echo "Or the fix-and-run script:"
echo "  ./scripts/fix-and-run.sh"
echo ""
echo "Note: Passwords are stored in environment variables and will be"
echo "      cleared when you close this shell."
