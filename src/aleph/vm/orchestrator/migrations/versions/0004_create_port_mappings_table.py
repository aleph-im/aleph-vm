"""create port_mappings table

Revision ID: a1b2c3d4e5f6
Revises: 2da719d72cea
Create Date: 2026-02-26 00:00:00.000000

"""

import json
import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy import create_engine, text
from sqlalchemy.engine import reflection

from aleph.vm.conf import make_db_url

revision = "a1b2c3d4e5f6"
down_revision = "2da719d72cea"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)


def upgrade() -> None:
    engine = create_engine(make_db_url())
    inspector = reflection.Inspector.from_engine(engine)
    tables = inspector.get_table_names()

    if "port_mappings" not in tables:
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
            "CREATE UNIQUE INDEX ix_port_mappings_host_port_active "
            "ON port_mappings (host_port) WHERE deleted_at IS NULL"
        )

    # Migrate existing data from executions.mapped_ports JSON
    if "executions" in tables:
        columns = inspector.get_columns("executions")
        column_names = [c["name"] for c in columns]
        if "mapped_ports" in column_names:
            now = datetime.now(tz=timezone.utc).isoformat()
            with engine.connect() as conn:
                rows = conn.execute(
                    text("SELECT vm_hash, mapped_ports FROM executions " "WHERE mapped_ports IS NOT NULL")
                ).fetchall()
                for vm_hash, mapped_ports_raw in rows:
                    if not mapped_ports_raw:
                        continue
                    mapped_ports = (
                        json.loads(mapped_ports_raw) if isinstance(mapped_ports_raw, str) else mapped_ports_raw
                    )
                    seen_host_ports = set()
                    for vm_port_str, details in mapped_ports.items():
                        vm_port = int(vm_port_str)
                        host_port = int(details.get("host", 0))
                        if host_port == 0:
                            continue
                        tcp = bool(details.get("tcp", False))
                        udp = bool(details.get("udp", False))
                        # Skip duplicate host_port (data inconsistency)
                        if host_port in seen_host_ports:
                            logger.warning(
                                "Skipping duplicate host_port %d for " "vm_hash=%s vm_port=%d",
                                host_port,
                                vm_hash,
                                vm_port,
                            )
                            continue
                        # Skip if host_port already taken by another VM
                        conflict = conn.execute(
                            text(
                                "SELECT vm_hash FROM port_mappings " "WHERE host_port = :hp " "AND deleted_at IS NULL"
                            ),
                            {"hp": host_port},
                        ).fetchone()
                        if conflict:
                            logger.warning(
                                "Skipping host_port %d for " "vm_hash=%s vm_port=%d " "(already used by %s)",
                                host_port,
                                vm_hash,
                                vm_port,
                                conflict[0],
                            )
                            continue
                        conn.execute(
                            text(
                                "INSERT INTO port_mappings "
                                "(vm_hash, vm_port, host_port, "
                                "tcp, udp, created_at) "
                                "VALUES (:vh, :vp, :hp, "
                                ":tcp, :udp, :ca)"
                            ),
                            {
                                "vh": vm_hash,
                                "vp": vm_port,
                                "hp": host_port,
                                "tcp": tcp,
                                "udp": udp,
                                "ca": now,
                            },
                        )
                        seen_host_ports.add(host_port)
                conn.commit()


def downgrade() -> None:
    op.drop_table("port_mappings")
