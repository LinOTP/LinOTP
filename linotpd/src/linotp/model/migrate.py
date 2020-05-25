# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

import linotp.model

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


def add_index(engine,table_name, index, column):
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


def run_data_model_migration(meta):
    """
    hook for database schema upgrade
     - called by flask init-db and during flask app bootstrap
    """

    # define the most recent target version
    target_version = "2.10.1.0"

    migration = Migration(meta)

    # start with the current version, which is retreived from the db
    current_version = migration.get_current_version()

    # run the steps in the migration chain
    migration.migrate(from_version=current_version, to_version=target_version)

    # finally set the target version we reached
    migration.set_version(target_version)

    return target_version

class Migration():
    """
    Migration class

    - support the the db migration with a chain of db migration steps
      where each step is defined as class method according to the requested
      target version

    """

    # model version key in the config table

    db_model_key = 'linotp.sql_data_model_version'

    # define the chain of migration steps starting with the not existing one

    migration_steps = [
        None,
        "2.9.1.0",
        "2.10.1.0"
        ]

    def __init__(self, meta):
        """
        class init
        - preserve the database handle
        """
        self.meta = meta
        self.current_version = None

    def _query_version(self):

        config_query= self.meta.Session.query(linotp.model.Config)
        config_query = config_query.filter(
                            linotp.model.Config.Key == self.db_model_key)

        return config_query.first()


    def get_current_version(self):
        """
        get the db model version number

        :return: current db version or None
        """

        if self.current_version:
            return self.current_version

        config_entry = self._query_version()

        if config_entry:

            # preserve the version, to not retrieve the version multiple times
            self.current_version = config_entry.Value

        return self.current_version

    def set_version(self, version):
        """
        set the version new db model number

        - on update: update the entry
        - on new: create new db entry

        :param version: set the new db model version
        """

        if version == self.current_version:
            return

        config_entry = self._query_version()

        if config_entry:
            config_entry.Value = version

        else:
            config_entry = linotp.model.Config(
                                        Key=self.db_model_key,
                                        Value=version)

        self.meta.Session.add(config_entry)


    def migrate(self, from_version, to_version):
        """
        run all migration steps between the versions, which
        are listed in the migration_steps

        :param from_version: the version to start in the migration chain
        :param to_version: the target version in the migration chain
        """

        active = False

        for next_version in self.migration_steps:

            if active:
                # --------------------------------------------------------- --

                # get the function pointer to the set version

                exec_version = next_version.replace('.', '_')
                function_name = 'migrate_%s' % exec_version

                if not hasattr(self, function_name):
                    log.error("unknown migration function %r",  function_name)
                    raise Exception('unknown migration to %r' % next_version)

                migration_step = getattr(self, function_name)

                # --------------------------------------------------------- --

                # execute the migration step

                try:
                    _success = migration_step()

                except Exception as exx:
                    log.exception('Failed to upgrade database! %r', exx)
                    self.meta.Session.rollback()
                    raise exx

            if next_version == from_version:
                active = True

            if next_version == to_version:
                break


    # --------------------------------------------------------------------- --

    # migration towards 2.9.1

    def migrate_2_9_1_0(self):
        """
        run the migration for bigger sized challenge column
        """

        challenge_table = "challenges"

        # add new bigger challenge column
        column = sa.Column('lchallenge', sa.types.Unicode(2000))

        if not has_column(self.meta, challenge_table, column):
            add_column(self.meta.engine, challenge_table, column)

        # add column to refer to the parent transaction
        column = sa.Column('ptransid', sa.types.Unicode(64), index=True)

        if not has_column(self.meta, challenge_table, column):
            add_column(self.meta.engine, challenge_table, column)
            add_index(self.meta.engine, challenge_table, 'ptransid', column)

    # --------------------------------------------------------------------- --

    # migration towards 2.10.1

    def migrate_2_10_1_0(self):
        """
        run the migration to blob challenge and data column
        """

        challenge_table = "challenges"

        # add new blob challenge column
        bchallenges = sa.Column('bchallenge', sa.types.Binary())

        if not has_column(self.meta, challenge_table, bchallenges):
            add_column(self.meta.engine, challenge_table, bchallenges)

        # add new blob data column
        bdata = sa.Column('bdata', sa.types.Binary())

        if not has_column(self.meta, challenge_table, bdata):
            add_column(self.meta.engine, challenge_table, bdata)


# eof
