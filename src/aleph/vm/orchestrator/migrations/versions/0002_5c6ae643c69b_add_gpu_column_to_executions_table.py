"""add gpu table

Revision ID: 5c6ae643c69b
Revises: bbb12a12372e
Create Date: 2024-12-09 19:40:19.279735

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
from sqlalchemy import create_engine
from sqlalchemy.engine import reflection

from aleph.vm.conf import make_db_url

revision = "5c6ae643c69b"
down_revision = "bbb12a12372e"
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
        if "gpus" not in column_names:
            op.add_column("executions", sa.Column("gpus", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("executions", "gpus")
