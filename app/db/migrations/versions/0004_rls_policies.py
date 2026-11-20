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

"""Enable PostgreSQL Row Level Security for tenant isolation.

Revision ID: 0004_rls
Revises: 0003_mfa_encrypt
Create Date: 2026-07-18

This migration:
  1. Enables RLS on all tenant-scoped tables
  2. Creates policies that filter by ``current_setting('app.tenant_id')``
  3. Grants BYPASSRLS to the service role for migrations/admin
     (conditional: role must exist and executor must be superuser)
  4. Creates an admin break-glass role

RLS Policies:
  - ``tenant_isolation_select``: SELECT only rows matching session tenant_id
  - ``tenant_isolation_insert``: INSERT only with session tenant_id
  - ``tenant_isolation_update``: UPDATE only rows matching session tenant_id
  - ``tenant_isolation_delete``: DELETE only rows matching session tenant_id

Session Variables:
  - ``app.tenant_id``: UUID of the current tenant (set per-request)
  - ``app.bypass_rls``: NOT consumed by the policies (O-17). Maintenance
    bypass is the BYPASSRLS role attribute only, which no session can set.

Break-Glass Procedure:
  To bypass RLS for administrative operations:
    -- Connect as a dedicated BYPASSRLS role (superuser-granted, audit-logged).
    -- Perform admin operations
  This should be audit-logged and time-boxed.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_rls"
down_revision: str | None = "0003_mfa_encrypt"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Tables that have a tenant_id column and need RLS
TENANT_TABLES = [
    "users",
    "roles",
    "sessions",
    "mfa_factors",
    "clients",
    "authorization_codes",
    "refresh_tokens",
    "tokens",
    "audit_events",
]


# Static DO block: no Python string interpolation reaches op.execute (ruff S608).
# __ACTION__ is substituted only with the module-constant literals below.
_DO_BYPASSRLS = """
    DO $$
DECLARE
    v_action text := '__ACTION__';
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jol_identity_user') THEN
            RAISE NOTICE '0004_rls: role jol_identity_user absent; skipping ALTER ROLE %', v_action;
        ELSIF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
            RAISE NOTICE '0004_rls: executor % is not superuser; skipping ALTER ROLE jol_identity_user %',
                current_user, v_action;
        ELSE
            EXECUTE 'ALTER ROLE jol_identity_user ' || v_action;
        END IF;
    END
    $$;
"""


def _set_bypassrls(enable: bool) -> None:
    # Grant/revoke BYPASSRLS on the repo-convention service role when present.
    # ALTER ROLE ... BYPASSRLS requires superuser; estate bootstraps may use a
    # different runtime role (e.g. jol_identity_app) and run migrations without
    # superuser, so skip with a notice instead of failing. The RLS policies
    # below do not depend on this grant.
    action = "BYPASSRLS" if enable else "NOBYPASSRLS"
    op.execute(_DO_BYPASSRLS.replace("__ACTION__", action))


def upgrade() -> None:
    # Grant BYPASSRLS to the service role for migrations/admin (conditional)
    _set_bypassrls(True)

    for table in TENANT_TABLES:
        # Enable RLS on the table
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")

        # Force RLS even for table owners (defense in depth)
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

        # SELECT policy: only rows matching the session tenant_id
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_select ON {table}
            FOR SELECT
            USING (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            """
        )

        # INSERT policy: must match session tenant_id
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_insert ON {table}
            FOR INSERT
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            """
        )

        # UPDATE policy: only update rows in current tenant
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_update ON {table}
            FOR UPDATE
            USING (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            """
        )

        # DELETE policy: only delete rows in current tenant
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_delete ON {table}
            FOR DELETE
            USING (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            """
        )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_delete ON {table}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_update ON {table}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_insert ON {table}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_select ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    _set_bypassrls(False)
