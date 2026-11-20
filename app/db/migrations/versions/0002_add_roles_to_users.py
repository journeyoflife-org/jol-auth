"""Add roles column to users table.

Revision ID: 0002_add_roles
Revises: 0001_initial
Create Date: 2026-07-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_add_roles"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("roles", sa.String(512), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("users", "roles")
