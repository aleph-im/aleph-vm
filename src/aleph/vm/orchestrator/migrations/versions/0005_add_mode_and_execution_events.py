"""Add mode column to executions and create execution_events table

Revision ID: b3c4d5e6f7a8
Revises: a1b2c3d4e5f6
Create Date: 2026-04-15 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import create_engine
from sqlalchemy.engine import reflection

from aleph.vm.conf import make_db_url

revision = "b3c4d5e6f7a8"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    engine = create_engine(make_db_url())
    inspector = reflection.Inspector.from_engine(engine)
    tables = inspector.get_table_names()

    # Add mode column to executions table
    if "executions" in tables:
        columns = inspector.get_columns("executions")
        column_names = [c["name"] for c in columns]
        if "mode" not in column_names:
            op.add_column(
                "executions",
                sa.Column("mode", sa.String(), nullable=False, server_default="normal"),
            )

    # Create execution_events audit table
    if "execution_events" not in tables:
        op.create_table(
            "execution_events",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("vm_hash", sa.String(), nullable=False),
            sa.Column("event_type", sa.String(), nullable=False),
            sa.Column("timestamp", sa.DateTime(), nullable=False),
            sa.Column("detail_json", sa.String(), nullable=True),
        )
        op.create_index(
            "ix_execution_events_vm_hash",
            "execution_events",
            ["vm_hash"],
        )


def downgrade() -> None:
    op.drop_table("execution_events")
    op.drop_column("executions", "mode")
