# S1 Remediation Guide — jol-auth Database Password Rotation

**Date:** 2026-09-19
**Status:** 🔴 CRITICAL — IMMEDIATE ACTION REQUIRED
**Severity:** HIGH — Real database passwords in version control

---

## Problem Statement

Database passwords are hardcoded in bootstrap scripts at:
- `scripts/bootstrap-jol-auth.sh` (lines 175, 212)
- `scripts/fix-and-run.sh` (line 69)

**Impact:**
- Violates AGENTS.md §0.1 (secret management)
- Violates SOC 2 CC6.1 (logical access controls)
- Violates ISO 27001 A.9.2 (user access management)
- Potential data breach if repo is compromised

---

## Remediation Steps

### Step 1: Rotate Database Passwords (IMMEDIATE)

**On the production database server:**

```bash
# Generate new passwords
openssl rand -base64 32  # Save as NEW_LT_PASSWORD
openssl rand -base64 32  # Save as NEW_IDENTITY_PASSWORD

# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Rotate jol_lt_platform_prod password
ALTER USER jol_lt_app_user WITH PASSWORD 'NEW_LT_PASSWORD';

# Rotate jol_identity password
ALTER USER jol_identity_user WITH PASSWORD 'NEW_IDENTITY_PASSWORD';

\q
```

### Step 2: Update Ansible Vault

**On the jol-auth repo:**

```bash
cd /opt/jol/repos/jol-auth

# Edit the vault file
vim ansible/group_vars/jol_auth/vault.yml

# Replace placeholder values with new passwords from Step 1

# Encrypt the vault file
ansible-vault encrypt ansible/group_vars/jol_auth/vault.yml
# Enter vault password when prompted

# Commit the encrypted vault
git add ansible/group_vars/jol_auth/vault.yml
git commit -m "security: Add encrypted vault for database credentials

- Replaces hardcoded passwords in bootstrap scripts
- Passwords rotated on 2026-09-19
- Addresses S1 finding from security audit"
```

### Step 3: Update Bootstrap Scripts

**Replace hardcoded passwords with environment variables:**

The bootstrap scripts need to be updated to read passwords from environment variables or Vault, not hardcoded values.

**Option A: Use environment variables (simpler)**

Create a wrapper script that loads Vault variables:

```bash
#!/bin/bash
# scripts/run-with-vault.sh

# Decrypt vault and export as environment variables
export JOL_LT_DB_PASSWORD=$(ansible-vault view ansible/group_vars/jol_auth/vault.yml | grep vault_jol_lt_db_password | cut -d'"' -f2)
export JOL_IDENTITY_DB_PASSWORD=$(ansible-vault view ansible/group_vars/jol_auth/vault.yml | grep vault_jol_identity_db_password | cut -d'"' -f2)

# Run the bootstrap script
./scripts/bootstrap-jol-auth.sh
```

Then update the bootstrap scripts to use `${JOL_LT_DB_PASSWORD}` and `${JOL_IDENTITY_DB_PASSWORD}` instead of hardcoded values.

**Option B: Convert to Ansible playbooks (recommended)**

Convert the bootstrap scripts to Ansible playbooks that can directly use Vault variables.

### Step 4: Add Pre-commit Hook

The pre-commit hook is already configured in `.pre-commit-config.yaml`. Verify it's working:

```bash
# Test that detect-secrets catches hardcoded passwords
echo "test_password = 'hardcoded_secret'" > test.txt
git add test.txt
git commit -m "test"  # Should FAIL with secret detection error
rm test.txt
```

### Step 5: Audit Git History

**Check if passwords were exposed in prior commits:**

```bash
# Search git history for the old passwords
git log -p --all -S 'OLD_PASSWORD_1'
git log -p --all -S 'OLD_PASSWORD_2'
```

**If found in history:**

```bash
# Option A: Rewrite history (destructive, requires force-push)
# WARNING: Only do this if you understand the implications
pip install bfg-repo-cleaner
bfg --replace-text passwords.txt .
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force

# Option B: Accept the risk (if repo is private and access is limited)
# Document the exposure and move on
```

### Step 6: Verify Remediation

```bash
# 1. No hardcoded passwords in scripts
grep -r "OLD_PASSWORD_1\|OLD_PASSWORD_2" scripts/
# Expected: NO RESULTS

# 2. Vault file exists and is encrypted
ls -la ansible/group_vars/jol_auth/vault.yml
head -1 ansible/group_vars/jol_auth/vault.yml
# Expected: $ANSIBLE_VAULT;1.1;AES256

# 3. Pre-commit hook works
# Test with a dummy secret (should fail)

# 4. Database passwords have been rotated
# Connect to database and verify password works with new credentials
```

---

## Verification Commands

To verify the remediation is complete:

```bash
# 1. No hardcoded passwords in scripts
grep -r "OLD_PASSWORD" /opt/jol/repos/jol-auth/scripts/
# Expected: NO RESULTS

# 2. Vault file exists and is encrypted
ls -la /opt/jol/repos/jol-auth/ansible/group_vars/jol_auth/vault.yml
head -1 /opt/jol/repos/jol-auth/ansible/group_vars/jol_auth/vault.yml
# Expected: $ANSIBLE_VAULT;1.1;AES256

# 3. Pre-commit hook is configured
grep -A2 "detect-secrets" /opt/jol/repos/jol-auth/.pre-commit-config.yaml
# Expected: detect-secrets hook configuration

# 4. Database passwords have been rotated
# Connect to database and verify password works with new credentials
```

---

## Compliance Impact

| Framework | Requirement | Before | After |
|-----------|-------------|--------|-------|
| **SOC 2** | CC6.1 (logical access) | 🔴 FAIL | ✅ PASS |
| **ISO 27001** | A.9.2 (user access) | 🔴 FAIL | ✅ PASS |
| **GDPR** | Art. 32 (security) | 🔴 FAIL | ✅ PASS |

---

## Rollback Plan

If remediation fails:

1. Restore scripts from git:
   ```bash
   git checkout HEAD~1 scripts/
   ```

2. Restore database passwords to old values (if already rotated):
   ```sql
   -- Use the old passwords from git history
   ALTER USER jol_lt_app_user WITH PASSWORD 'OLD_PASSWORD_1';
   ALTER USER jol_identity_user WITH PASSWORD 'OLD_PASSWORD_2';
   ```

3. Remove vault file:
   ```bash
   rm -rf ansible/
   ```

---

## Sign-off

- [ ] Database passwords rotated
- [ ] Vault file created and encrypted
- [ ] Bootstrap scripts updated
- [ ] Pre-commit hook verified
- [ ] Git history audited
- [ ] Verification commands pass
- [ ] Compliance impact documented

**Remediated by:** _________________
**Date:** _________________
**Reviewed by:** _________________
**Date:** _________________

---

**Status:** 🔴 PENDING — Requires production database access
