"""add mapped_ports column

Revision ID: 2da719d72cea
Revises: 5c6ae643c69b
Create Date: 2025-05-29 23:20:42.801850

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "2da719d72cea"
down_revision = "5c6ae643c69b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("executions", sa.Column("mapped_ports", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("executions", "mapped_ports")
