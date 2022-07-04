"""create column 'execution_uuid'

Revision ID: a68d6198a6d6
Revises: 
Create Date: 2022-07-04 17:51:59.533155

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
from vm_supervisor.metrics import ExecutionRecord

revision = 'a68d6198a6d6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(ExecutionRecord.__tablename__,
                  sa.Column('execution_uuid', sa.String, nullable=False)
                  )


def downgrade() -> None:
    op.drop_column(table_name=ExecutionRecord.__tablename__,
                   column_name='execution_uuid')

