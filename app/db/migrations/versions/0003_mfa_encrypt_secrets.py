"""MFA: rename secret_hash to secret_encrypted, add recovery_codes.

Revision ID: 0003_mfa_encrypt
Revises: 0002_add_roles
Create Date: 2026-07-18

This migration:
  1. Renames ``secret_hash`` → ``secret_encrypted`` (Text, not String(255))
  2. Adds ``recovery_codes`` column (nullable Text)

Data migration:
  Existing TOTP secrets were hashed with Argon2id and are unrecoverable.
  The ``secret_encrypted`` column is set to an empty string for existing
  rows — those factors are broken and users must re-enroll MFA.
  The ``is_verified`` flag is set to False for all existing factors to
  force re-enrollment.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_mfa_encrypt"
down_revision: str | None = "0002_add_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add the new column first (nullable so existing rows don't fail)
    op.add_column(
        "mfa_factors",
        sa.Column("secret_encrypted", sa.Text(), nullable=True),
    )

    # Copy data from secret_hash to secret_encrypted — BUT hashed secrets
    # are unrecoverable.  Set to empty string and force re-enrollment.
    op.execute("UPDATE mfa_factors SET secret_encrypted = '' WHERE secret_encrypted IS NULL")
    op.execute("UPDATE mfa_factors SET is_verified = false WHERE secret_encrypted = ''")

    # Make the column NOT NULL
    op.alter_column(
        "mfa_factors",
        "secret_encrypted",
        nullable=False,
    )

    # Drop the old column
    op.drop_column("mfa_factors", "secret_hash")

    # Add recovery_codes column
    op.add_column(
        "mfa_factors",
        sa.Column("recovery_codes", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    # Restore old column
    op.add_column(
        "mfa_factors",
        sa.Column("secret_hash", sa.String(255), nullable=True),
    )
    op.execute("UPDATE mfa_factors SET secret_hash = '' WHERE secret_hash IS NULL")
    op.alter_column(
        "mfa_factors",
        "secret_hash",
        nullable=False,
    )
    op.drop_column("mfa_factors", "recovery_codes")
    op.drop_column("mfa_factors", "secret_encrypted")
