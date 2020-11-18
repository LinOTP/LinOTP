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
import logging

from typing import Union

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from sqlalchemy import inspect

from linotp import model

log = logging.getLogger(__name__)


def has_column(engine:Engine, table_name:str, column:sa.Column) -> bool:
    """Check the column is already in the table.

    :param engine: database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: boolean

    """

    insp = inspect(engine)
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

def _compile_name(name:str, dialect=None) -> str:
    """Helper - to adjust the names of table / column / index to quoted or not.

    in postgresql the tablenames / column /index names must be quotes
    while not so in mysql

    :param name: tablename, index name of column name
    :param engine: the corresponding engine for mysql / postgresql
    :return: the adjusted name
    """
    return sa.Column(name, sa.types.Integer()).compile(dialect=dialect) # pylint: disable=E1120

def add_column(engine:Engine, table_name:str, column:sa.Column):
    """Create an index based on the column index definition.

    calling the compiled SQL statement:

        ALTER TABLE table_name ADD COLUMN column_name column_type

    :param engine: the bound sql database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: - nothing -

    """

    c_table_name = _compile_name(table_name, dialect=engine.dialect)

    c_column_name = column.compile(dialect=engine.dialect)
    c_column_type = column.type.compile(engine.dialect)

    engine.execute('ALTER TABLE %s ADD COLUMN %s %s' %
                   (c_table_name, c_column_name, c_column_type))


def add_index(engine:Engine, table_name:str, column:sa.Column):
    """Create an index based on the column index definition

    calling the compiled SQL statement:

        CREATE INDEX index_name
        ON table_name (column_name)

    :param engine: the bound sql database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column definition

    :return: - nothing -

    """

    c_table_name = _compile_name(table_name, dialect=engine.dialect)

    c_column_name = column.compile(dialect=engine.dialect)

    index_name = "ix_%s_%s" % (table_name, column.name)
    c_index_name = _compile_name(index_name, dialect=engine.dialect)

    engine.execute('CREATE INDEX %s ON %s ( %s )' %
                   (c_index_name, c_table_name, c_column_name))


def drop_column(engine:Engine, table_name:str, column:sa.Column):
    """

    calling the compiled SQL statement

        ALTER TABLE table_name drop COLUMN column

    :param engine: the bound sql database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: - nothing -

    """

    c_table_name = _compile_name(table_name, dialect=engine.dialect)

    c_column_name = column.compile(dialect=engine.dialect)
    engine.execute('ALTER TABLE %s drop COLUMN %s ' %
                   (c_table_name, c_column_name))


def re_encode(
        value:str, from_encoding:str='iso-8859-15',
        to_encoding:str='utf-8') -> str:
    """Reencode a value by default from iso-8859 to utf-8.

    Remark:
    We have only bytes here comming from LinOTP2 stored by python2
    and sqlalchemy. The observation is that under certain
    circumstances the stored data is iso-8859 encoded but sometimes
    could as well be utf-8.

    In python3 this data is now loaded into a str object which is a
    utf-8 encoded string. A conversion from iso-8859 to utf-8 does not
    fail as all codepoints of iso-8859 are within utf-8 range. But the
    result in a bad representation as the codepoints of iso-8859 and
    utf-8 dont match.

    * we are using here iso-8859-15 which is a superset of iso-8859-1
      which is a superset of ascii

    :param value: str data, might contain iso-8859 data
    :param from_encoding: str data encoding, default 'iso8859-15'
    :param to_encoding: str data output encoding, default 'utf-8'
    """

    if not value or not isinstance(value, str):
        return value

    if value.isascii():
        return value

    try:
        value = bytes(value, from_encoding).decode(to_encoding)
    except UnicodeDecodeError:
        log.info(
            'unable to re-encode value: %r - might be already %r',
            value, to_encoding
            )
        raise

    return value

# ------------------------------------------------------------------------- --

# entry point for calling db migration

def run_data_model_migration(engine:Engine):
    """
    hook for database schema upgrade
     - called during database initialisation
    """

    # define the most recent target version
    target_version = "2.12.0.0"

    migration = Migration(engine)

    # start with the current version, which is retrieved from the db
    current_version = migration.get_current_version()

    # run the steps in the migration chain
    migration.migrate(from_version=current_version, to_version=target_version)

    # finally set the target version we reached
    migration.set_version(target_version)

    return target_version

class Migration():
    """Migration class.

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
        "2.10.1.0",
        "2.12.0.0",
        ]

    def __init__(self, engine:Engine):
        """Class init.

        - preserve the database handle / engine
        """
        self.engine = engine
        self.current_version = None

    @staticmethod
    def _query_db_model_version() -> "model.Config":
        """Get the current db model version."""
        return model.Config.query.filter_by(Key=Migration.db_model_key).first()

    @staticmethod
    def is_db_model_current() -> bool:
        """Check if the db model is current by comparing the db entry."""

        target_version = Migration.migration_steps[-1]

        current_version = Migration._query_db_model_version()
        if current_version:
            current_version = current_version.Value

        return target_version == current_version

    def get_current_version(self) -> Union[str, None]:
        """Get the db model version number.

        :return: current db version or None
        """

        if self.current_version:
            return self.current_version

        config_entry = Migration._query_db_model_version()

        if not config_entry:
            return None

        # preserve the version, to not retrieve the version multiple times
        self.current_version = config_entry.Value

        return self.current_version

    def set_version(self, version:str):
        """Set the new db model version number.

        - on update: update the entry
        - on new: create new db entry

        :param version: set the new db model version
        """

        if version == self.current_version:
            return

        config_entry = Migration._query_db_model_version()

        if config_entry:
            config_entry.Value = version
        else:
            config_entry = model.Config(Key=self.db_model_key, Value=version)

        model.db.session.add(config_entry) # pylint: disable=E1101

    def migrate(self, from_version:Union[str, None], to_version:str):
        """Run all migration steps between the versions.

        run all steps, which are of ordered list migration_steps

        :param from_version: the version to start in the migration chain
        :param to_version: the target version in the migration chain
        """

        active = False

        for next_version in self.migration_steps:

            if next_version and active:

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
                    model.db.session.rollback() # pylint: disable=E1101
                    raise exx

            if next_version == from_version:
                active = True

            if next_version == to_version:
                break


    # --------------------------------------------------------------------- --

    # migration towards 2.9.1

    def migrate_2_9_1_0(self):
        """Run the migration for bigger sized challenge column."""

        challenge_table = "challenges"

        # add new bigger challenge column
        column = sa.Column('lchallenge', sa.types.Unicode(2000))

        if not has_column(self.engine, challenge_table, column):
            add_column(self.engine, challenge_table, column)

        # add column to refer to the parent transaction
        column = sa.Column('ptransid', sa.types.Unicode(64), index=True)

        if not has_column(self.engine, challenge_table, column):
            add_column(self.engine, challenge_table, column)
            add_index(self.engine, challenge_table, column)

    # --------------------------------------------------------------------- --

    # migration towards 2.10.1

    def migrate_2_10_1_0(self):
        """Run the migration to blob challenge and data column."""

        challenge_table = "challenges"

        # add new blob challenge column
        bchallenges = sa.Column('bchallenge', sa.types.LargeBinary())

        if not has_column(self.engine, challenge_table, bchallenges):
            add_column(self.engine, challenge_table, bchallenges)

        # add new blob data column
        bdata = sa.Column('bdata', sa.types.LargeBinary())

        if not has_column(self.engine, challenge_table, bdata):
            add_column(self.engine, challenge_table, bdata)

    # migration towards 2.12.

    def migrate_2_12_0_0(self):
        """Run the migration for token to add the time stamps.

        time stamps are: created, accessed and verified
        """

        token_table = "Token"

        # add created column to tokens
        created = sa.Column(
            'LinOtpCreationDate', sa.types.DateTime, index=True)

        if not has_column(self.engine, token_table, created):
            add_column(self.engine, token_table, created)
            add_index(self.engine, token_table, created)

        # add verified column to tokens
        verified = sa.Column(
            'LinOtpLastAuthSuccess', sa.types.DateTime, index=True)

        if not has_column(self.engine, token_table, verified):
            add_column(self.engine, token_table, verified)
            add_index(
                self.engine, token_table, verified)

        # add accessed column to tokens
        accessed = sa.Column(
            'LinOtpLastAuthMatch', sa.types.DateTime, index=True)

        if not has_column(self.engine, token_table, accessed):
            add_column(self.engine, token_table, accessed)
            add_index(self.engine, token_table, accessed)

# eof
