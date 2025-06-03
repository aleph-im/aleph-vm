"""add mapped_ports column

Revision ID: 2da719d72cea
Revises: 5c6ae643c69b
Create Date: 2025-05-29 23:20:42.801850

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
from sqlalchemy import create_engine
from sqlalchemy.engine import reflection

from aleph.vm.conf import make_db_url

# revision identifiers, used by Alembic.
revision = "2da719d72cea"
down_revision = "5c6ae643c69b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    engine = create_engine(make_db_url())
    inspector = reflection.Inspector.from_engine(engine)

    # The table already exists on most CRNs.
    tables = inspector.get_table_names()
    if "executions" in tables:
        columns = inspector.get_columns("executions")
        column_names = [c["name"] for c in columns]
        if "mapped_ports" not in column_names:
            op.add_column("executions", sa.Column("mapped_ports", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("executions", "mapped_ports")
