"""drop the vestigial port_mappings table from the agent DB

Revision ID: f1a2b3c4d5e6
Revises: a1b2c3d4e5f6
Create Date: 2026-06-24 00:00:00.000000

Port mappings moved to the supervisor's own database. On its first start
after that split, the supervisor daemon copies the active rows OUT of this
agent-DB table (networking_db.migrate_port_mappings_from_legacy_db and its
Rust counterpart). The copy skips itself for good once the supervisor table
holds any row, so from that point the legacy rows are dead data and the table
can go.

The drop is gated on that same condition rather than on release ordering: it
only happens when the copy can no longer need the legacy rows, and it FAILS
otherwise. A failed startup migration exits the agent non-zero, systemd
restarts it, and the next attempt re-checks. So an agent that comes up before
its daemon has run the copy simply waits for it instead of destroying live
VMs' host-port forwards. This also makes the migration safe on any upgrade
path, including a node skipping releases straight past the split.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

from aleph.vm.conf import settings

revision = "f1a2b3c4d5e6"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def _supervisor_store_is_populated(path: Path) -> bool:
    """True once the supervisor DB holds any port_mappings row: the copy has
    run (or new mappings exist), and it will never read the legacy table again."""
    if not path.exists():
        return False
    # Read-only: this is the supervisor's file, the agent only peeks at it.
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as conn:
        try:
            return conn.execute("SELECT 1 FROM port_mappings LIMIT 1").fetchone() is not None
        except sqlite3.OperationalError:
            return False  # schema not created yet


def _legacy_has_active_rows(bind: sa.engine.Connection) -> bool:
    row = bind.execute(text("SELECT 1 FROM port_mappings WHERE deleted_at IS NULL LIMIT 1")).fetchone()
    return row is not None


def upgrade() -> None:
    bind = op.get_bind()
    if "port_mappings" not in sa.inspect(bind).get_table_names():
        return

    legacy = Path(settings.EXECUTION_DATABASE)
    supervisor = Path(settings.SUPERVISOR_DATABASE)
    if legacy == supervisor:
        # Single shared file: this table IS the supervisor's live store.
        return

    if _legacy_has_active_rows(bind) and not _supervisor_store_is_populated(supervisor):
        raise RuntimeError(
            f"refusing to drop the legacy port_mappings table from {legacy}: it still holds active "
            f"host-port forwards and the supervisor store {supervisor} has not received them yet. "
            "Start the aleph-vm-supervisor daemon (it copies them on startup), then start the agent again."
        )

    # The supervisor DB is the authority now; this agent-DB copy is unused.
    # No explicit drop_index: on SQLite, DROP TABLE also drops the table's indexes.
    op.drop_table("port_mappings")


def downgrade() -> None:
    bind = op.get_bind()
    if "port_mappings" in sa.inspect(bind).get_table_names():
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
