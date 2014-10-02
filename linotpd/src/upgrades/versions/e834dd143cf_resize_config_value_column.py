"""add client column to audit table

Revision ID: e834dd143cf
Revises: None
Create Date: 2014-10-02 11:45:19.500514

"""

# revision identifiers, used by Alembic.
revision = 'e834dd143cf'
down_revision = None
audit_table_name = 'audit'

from alembic import op
import sqlalchemy as sa
from sqlalchemy import MetaData
from upgrades.util import get_audit_table_name
from upgrades.util import table_has_column


def upgrade(engine_name):
    globals()["upgrade_%s" % engine_name]()

def downgrade(engine_name):
    globals()["downgrade_%s" % engine_name]()


def upgrade_linotp():
    pass

def downgrade_linotp():
    pass

def upgrade_audit():
    # try: if the clients column is already the audit table
    engine = op.get_bind().engine

    # first get all potential audit tables
    audit_table_names = get_audit_table_name(engine)

    for audit_table_name in audit_table_names:
        # check if there is already a client column
        if table_has_column(engine, audit_table_name, 'client') == False:
            op.add_column(audit_table_name, sa.Column('client', sa.types.Unicode(length=80)))

    return


def downgrade_audit():

    # audit_table_names = get_audit_table_names()
    # for audit_table_name in audit_table_names:
    #    op.drop_column(audit_table_name, 'client')

    return

def upgrade_openid():
    pass


def downgrade_openid():
    pass

