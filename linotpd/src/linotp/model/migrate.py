# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""
database schema migration hook
"""


import sqlalchemy as sa

from sqlalchemy.exc import ProgrammingError
from sqlalchemy.exc import OperationalError

from sqlalchemy import inspect

import logging

log = logging.getLogger(__name__)


def has_column(meta, table_name, column):
    """
    check the column is already in the table

    :param meta: the meta context with engine++
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: boolean

    """

    insp = inspect(meta.engine)
    tables = insp.get_table_names()
    if table_name not in tables:
        return False

    #
    # get the list of all columns with their description as dict

    columns = insp.get_columns(table_name)
    for column_item in columns:
        if column_item.get('name') == column.name:
            return True
    return False


def add_column(engine, table_name, column):
    """
    create an index based on the column index definition

    calling the compiled SQL statement:

        ALTER TABLE table_name ADD COLUMN column_name column_type

    :param engine: the bound sql database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: - nothing -

    """
    column_name = column.compile(dialect=engine.dialect)
    column_type = column.type.compile(engine.dialect)
    engine.execute('ALTER TABLE %s ADD COLUMN %s %s' %
                   (table_name, column_name, column_type))


def add_index(engine, index, table_name, column):
    """
    create an index based on the column index definition

    calling the compiled SQL statement:

        CREATE INDEX index_name
        ON table_name (column_name)

    :param engine: the bound sql database engine
    :param index: the name of the index - string
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: - nothing -

    """

    column_name = column.compile(dialect=engine.dialect)
    column_index = "ix_%s_%s" % (table_name, column_name)
    engine.execute('CREATE INDEX %s ON %s ( %s )' %
                   (column_index, table_name, column_name))


def drop_column(engine, table_name, column):
    """

    calling the compiled SQL statement

        ALTER TABLE table_name drop COLUMN column

    :param engine: the bound sql database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: - nothing -

    """

    column_name = column.compile(dialect=engine.dialect)
    engine.execute('ALTER TABLE %s drop COLUMN %s ' %
                   (table_name, column_name))


def run_data_model_migration(meta, target_version=None):
    """
    hook for database schema upgrade
    """

    if target_version and target_version == "2.9.1.0":
        try:

            # add new bigger sized challenge column
            column = sa.Column('lchallenge', sa.types.Unicode(2000))

            if not has_column(meta, 'challenges', column):
                add_column(meta.engine, 'challenges', column)

            # add column to refer to the parent transaction
            column = sa.Column('ptransid', sa.types.Unicode(64), index=True)

            if not has_column(meta, 'challenges', column):
                add_column(meta.engine, 'challenges', column)
                add_index(meta.engine, 'ptransid', 'challenges', column)

        except ProgrammingError as exx:
            log.exception('Failed to upgrade database! %r', exx)

        except OperationalError as exx:
            log.exception('Failed to upgrade database! %r', exx)

        except Exception as exx:
            log.exception('Failed to upgrade database! %r', exx)
            raise exx

    return
