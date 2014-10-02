import traceback


from alembic import op
import sqlalchemy as sa
from sqlalchemy import MetaData


def where_from():

    lines = traceback.format_stack()
    for line in lines:
        if 'run_migrations_offline()' in line:
            mode = 'offline'
            break
        if 'run_migrations_online' in line:
            mode = 'online'
            break

    return mode


def get_audit_table_name(engine):
    """
    get the name of the audit table - semi correct :-[

    we have no access to the config entry for the audit.table_prefix

    so we try to get all tables named audit in the auditdb or
    those postfixed with 'audit' and which have the column 'clearance_level'

    !!! this will fail, if there are copies of the auit_tables !!!


    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    in the offline mode the script generator uses as well reflection
    which will break our investigation - so we check in the callstack
    if we are in the offline mode and will return only a simple 'audit'
    which the operator has to adjust
    in online mode we can try to find the correct audit tables via reflection
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    """

    if 'offline' == where_from():
        return ['audit']

    engine = op.get_bind().engine
    m = MetaData()

    m.reflect(engine)
    table_names = m.tables.keys()
    if 'audit' in table_names:
        return ['audit']

    audit_tables = []

    for table_name in table_names:
        # does the table have a prefix followd by 'audit'
        if table_name[-len('audit'):] == 'audit':
            cols = m.tables.get(table_name).c
            if 'clearance_level' in cols:
                audit_tables.append(table_name)

    return audit_tables

def table_has_column(engine, table_name, column_name):

    if 'offline' == where_from():
        return False

    m = MetaData()

    m.reflect(engine)
    cols = m.tables.get(table_name).c
    if column_name in cols:
        return True
    else:
        return False

