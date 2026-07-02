"""drop the vestigial port_mappings table from the agent DB

Revision ID: f1a2b3c4d5e6
Revises: a1b2c3d4e5f6
Create Date: 2026-06-24 00:00:00.000000

DO NOT MERGE/DEPLOY until the agent/supervisor DB split has shipped to ALL
nodes. Port mappings moved to the supervisor's own database; on first start
after the split the supervisor copies the rows OUT of this agent-DB table
(see supervisor.networking_db.migrate_port_mappings_from_legacy_db). This
migration drops that source table, so deploying it before every node has run
the copy would destroy live VMs' host-port forwards. It is the second phase of
a two-phase migration: copy in the split release, drop here in a later one.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import create_engine
from sqlalchemy.engine import reflection

from aleph.vm.conf import make_db_url

revision = "f1a2b3c4d5e6"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    engine = create_engine(make_db_url())
    inspector = reflection.Inspector.from_engine(engine)
    if "port_mappings" not in inspector.get_table_names():
        return
    # The supervisor DB is the authority now; this agent-DB copy is unused.
    # No explicit drop_index: on SQLite, DROP TABLE also drops the table's indexes.
    op.drop_table("port_mappings")


def downgrade() -> None:
    engine = create_engine(make_db_url())
    inspector = reflection.Inspector.from_engine(engine)
    if "port_mappings" in inspector.get_table_names():
        return
    # Mirror the table creation from 0004_create_port_mappings_table.py exactly,
    # so that upgrade then downgrade round-trips to the canonical schema.
    op.create_table(
        "port_mappings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("vm_hash", sa.String(), nullable=False, index=True),
        sa.Column("vm_port", sa.Integer(), nullable=False),
        sa.Column("host_port", sa.Integer(), nullable=False),
        sa.Column("tcp", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("udp", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
    )
    # Unique host_port among active (non-deleted) rows only
    op.execute(
        "CREATE UNIQUE INDEX ix_port_mappings_host_port_active " "ON port_mappings (host_port) WHERE deleted_at IS NULL"
    )
