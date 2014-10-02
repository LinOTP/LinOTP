"""extend Config Value column

Revision ID: d21455fbe5f
Revises: e834dd143cf
Create Date: 2014-10-02 18:04:44.493146

"""

# revision identifiers, used by Alembic.
revision = 'd21455fbe5f'
down_revision = 'e834dd143cf'

from alembic import op
import sqlalchemy as sa
from sqlalchemy import MetaData


def upgrade(engine_name):
    globals()["upgrade_%s" % engine_name]()


def downgrade(engine_name):
    globals()["downgrade_%s" % engine_name]()

def upgrade_linotp():
    op.alter_column(
        table_name='Config',
        column_name='Value',
        nullable=True,
        type_=sa.types.Unicode(length=3000),
    )

def downgrade_linotp():
    op.alter_column(
        table_name='Config',
        column_name='Value',
        nullable=True,
        type_=sa.types.Unicode(length=2000),
    )


def upgrade_audit():
    pass

def downgrade_audit():
    pass

def upgrade_openid():
    pass

def downgrade_openid():
    pass

