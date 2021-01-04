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

from typing import Optional

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

# mysql specific migration

class MYSQL_Migration():
    """MYSQL schema and data migration - converting from latin1 to utf8."""

    def __init__(self, engine):
        self.engine = engine

    def _execute(self, command):
        """helper to execute the lowlevel sql command and return result.

        :param command: the raw sql command
        :return: the sqlalchemy result (proxy)
        """
        return self.engine.connect().execute(text(command))

    # --------------------------------------------------------------------- --

    # schema conversion

    def _query_schema(self, table):
        """Query the mysql for the table creation defintion.

        the result contains the charset which might be latin1 or utf8
        :param table: the table name
        """
        results = self._execute(f"SHOW CREATE TABLE {table};")
        return results.next()[1]

    def _update_schema(self, table):
        """Update the table defintion to utf8 charset.

        :param table: the table name
        """
        return self._execute(
            f"ALTER TABLE {table} CONVERT TO CHARACTER SET utf8mb4;")

    def _get_tables(self):
        """Query the linotp database for all tables.

        :yield: table name
        """
        for result in self._execute("show tables;"):
            yield result[0]

    def migrate_schema(self):
        """Migration worker, to update the schema definition.

        mysql 'show create table' returns a string which contains as well the
        used table chareset. In case of a latin1 charset, we convert this
        table defintion to utf8.

        :return: list of migrated tables
        """
        migrated_tables = []

        for table in self._get_tables():
            schema_def =  self._query_schema(table)
            table_desc = schema_def.rpartition(')')[2]
            if 'CHARSET=latin1' in table_desc:
                self._update_schema(table)
                migrated_tables.append(table)

        return migrated_tables

    # --------------------------------------------------------------------- --

    # data conversion

    def _convert(self, column):
        """Helper to build conversion string.

        :param column: the string name of the column
        :return: the composed conversion string
        """
        return (f"{column} = CONVERT(CAST(CONVERT({column} "
                "USING latin1) as BINARY) USING utf8)")

    def _convert_Config_to_utf8(self):
        """Migrate the Config Value and Description to utf8."""
        cmd = (
            "Update Config Set %s, %s ;" % (
            self._convert("Config.Description"),
            self._convert("Config.Value")
            ))
        return self._execute(cmd)

    def _convert_Token_to_utf8(self):
        """Migrate the Token Description and LinOtpTokenInfo to utf8."""
        cmd = ("Update Token Set %s, %s ;" % (
            self._convert("Token.LinOtpTokenDesc"),
            self._convert("Token.LinOtpTokenInfo")
            ))
        return self._execute(cmd)

    def migrate_data(self, tables):
        """Worker for the data migration.

        :param tables: list of tables where the data should be converted to utf8
        """
        if 'Config' in tables:
            self._convert_Config_to_utf8()
        if 'Token' in tables:
            self._convert_Token_to_utf8()

# ------------------------------------------------------------------------- --

# entry point for calling db migration

def run_data_model_migration(engine:Engine):
    """
    hook for database schema upgrade
     - called during database initialisation
    """

    migration = Migration(engine)

    # run the steps in the migration chain
    target_version = migration.migrate()

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
        "3.0.0.0",
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

    @staticmethod
    def is_db_untouched() -> bool:
        """Check if the db was just created or has been used already.

        When linotp has been run once, it contains the 'linotp.Config' entry
        which is a timestamp about the last config entry change.
        If the entry does not exist, we can be sure, that the db has not been
        touched.
        """

        return model.Config.query.filter(
            model.Config.Key == 'linotp.Config').first() is None

    def get_current_version(self) -> Optional[str]:
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

    def migrate(
            self, from_version:Optional[str]=None,
            to_version:Optional[str]=None
            ) -> str:
        """Run all migration steps between the versions.

        run all steps, which are of ordered list migration_steps

        :param from_version: the version to start in the migration chain
        :param to_version: the target version in the migration chain
        """

        # if no from version , we start with the current version,
        #   which is retrieved from the db

        if from_version is None:
            from_version = self.get_current_version()

        # if no target version is define we take
        #   the most recent target version

        if to_version is None:
            to_version = Migration.migration_steps[-1]


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

        return to_version

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

    # migration towards 3.0

    def migrate_3_0_0_0(self):
        """Create a conversion suggested label if db is not untouched."""

        if not self.is_db_untouched():

            config_entry = model.Config(
                Key='utf8_conversion', Value='suggested'
                )
            model.db.session.add(config_entry)

            log.warning(
                "Database conversion step suggested!\n"
                "Please run command:\n"
                " linotp admin fix-db-encoding")

        return

    def iso8859_to_utf8_conversion(self):
        """Migrate all Config and Token entries from iso-8859 to utf-8."""

        conversion = model.Config.query.filter(
            model.Config.Key == 'linotp.utf8_conversion').first()

        if not conversion or conversion.Value != 'suggested':
            return True, "no conversion required or suggested!"

        # ------------------------------------------------------------------ --

        # re-encode the Config Values of certain Types

        config_entries_count = 0

        for entry in model.Config.query.all():

            if entry.Type in [
                'int', 'bool', 'boolean', 'encrypted_data', 'password'
                ]:
                continue

            update_data = {
                model.Config.Value: re_encode(entry.Value),
                model.Config.Description: re_encode(entry.Description),
            }

            # replace by the primary key: Key

            model.Config.query.filter(
                model.Config.Key == entry.Key
                ).update(update_data , synchronize_session = False)

            config_entries_count +=1

        log.info(f"{config_entries_count} config entries reencoded!")

        # ------------------------------------------------------------------ --

        # Reencode Token description and info from iso8895 to utf-8.

        token_entries_count = 0

        for token in model.Token.query.all():

            update_data = {
                model.Token.LinOtpTokenDesc: re_encode(
                    token.LinOtpTokenDesc),
                model.Token.LinOtpTokenInfo: re_encode(
                    token.LinOtpTokenInfo),
            }

            # replace by the primary key: LinOtpTokenId

            model.Token.query.filter(
                model.Token.LinOtpTokenId == token.LinOtpTokenId
                ).update(update_data , synchronize_session = False)

            token_entries_count +=1

        log.info(f"{token_entries_count} token entries reencoded!")

        summary = (f"{config_entries_count} config and "
                   f"{token_entries_count} token entries converted.")

        conversion = model.Config.query.filter(
            model.Config.Key == 'linotp.utf8_conversion').delete()

        return True, summary

# eof
