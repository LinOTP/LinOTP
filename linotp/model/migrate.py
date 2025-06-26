#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
database schema migration hook
"""

import binascii
import logging
from typing import Any

import sqlalchemy as sa
from flask import current_app
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from linotp import model

log = logging.getLogger(__name__)


def has_column(engine: Engine, table_name: str, column: sa.Column) -> bool:
    """Check the column is already in the table.

    :param engine: database engine
    :param table_name: the name of the table with the column
    :param column: the instantiated column defintion

    :return: boolean

    """

    insp = inspect(engine)
    tables = [tn.lower() for tn in insp.get_table_names()]
    if table_name.lower() not in tables:
        return False

    #
    # get the list of all columns with their description as dict

    columns = insp.get_columns(table_name)
    return any(column_item.get("name") == column.name for column_item in columns)


def _compile_name(name: str, dialect: str | None = None) -> str:
    """Helper - to adjust the names of table / column / index to quoted or not.

    in postgresql the tablenames / column /index names must be quotes
    while not so in mysql

    :param name: tablename, index name of column name
    :param engine: the corresponding engine for mysql / postgresql
    :return: the adjusted name
    """
    return sa.Column(name, sa.types.Integer()).compile(dialect=dialect)  # pylint: disable=E1120


def add_column(engine: Engine, table_name: str, column: sa.Column):
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

    with engine.connect() as connection:
        connection.execute(
            f"ALTER TABLE {c_table_name} ADD COLUMN {c_column_name} {c_column_type}"
        )


def add_index(engine: Engine, table_name: str, column: sa.Column) -> None:
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

    index_name = f"ix_{table_name}_{column.name}"
    c_index_name = _compile_name(index_name, dialect=engine.dialect)

    with engine.connect() as connection:
        connection.execute(
            f"CREATE INDEX {c_index_name} ON {c_table_name} ( {c_column_name} )"
        )


def drop_column(engine: Engine, table_name: str, column: sa.Column) -> None:
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
    with engine.connect() as connection:
        connection.execute(f"ALTER TABLE {c_table_name} drop COLUMN {c_column_name} ")


def re_encode(
    value: str, from_encoding: str = "iso-8859-15", to_encoding: str = "utf-8"
) -> str:
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
            "unable to re-encode value: %r - might be already %r",
            value,
            to_encoding,
        )
        raise

    return value


# ------------------------------------------------------------------------- --

# mysql specific migration


class MYSQL_Migration:
    """MYSQL schema and data migration - converting from latin1 to utf8."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def _execute(self, command: str) -> Any:
        """helper to execute the lowlevel sql command and return result.

        :param command: the raw sql command
        :return: the sqlalchemy result (proxy)
        """
        with self.engine.connect() as connection:
            return connection.execute(text(command))

    # --------------------------------------------------------------------- --

    # schema conversion

    def _query_schema(self, table: str) -> Any:
        """Query the mysql for the table creation defintion.

        the result contains the charset which might be latin1 or utf8
        :param table: the table name
        """
        with self.engine.connect() as connection:
            results = connection.execute(f"SHOW CREATE TABLE {table};")
            return results.fetchone()[1]

    def _update_schema(self, table: str) -> Any:
        """Update the table defintion to utf8 charset.

        :param table: the table name
        """
        with self.engine.connect() as connection:
            return connection.execute(
                f"ALTER TABLE {table} CONVERT TO CHARACTER SET utf8mb4;"
            )

    def _get_tables(self) -> Any:
        """Query the linotp database for all tables.

        :yield: list of tables in database
        """
        with self.engine.connect() as connection:
            for result in connection.execute("show tables;"):
                yield result[0]

    def migrate_schema(self) -> list:
        """Migration worker, to update the schema definition.

        mysql 'show create table' returns a string which contains as well the
        used table chareset. In case of a latin1 charset, we convert this
        table defintion to utf8.

        :return: list of migrated tables
        """
        migrated_tables = []

        for table in self._get_tables():
            schema_def = self._query_schema(table)
            table_desc = schema_def.rpartition(")")[2]
            if "CHARSET=latin1" in table_desc:
                self._update_schema(table)
                migrated_tables.append(table)

        return migrated_tables

    # --------------------------------------------------------------------- --

    # data conversion

    def _convert(self, column: str) -> str:
        """Helper to build conversion string.

        :param column: the string name of the column
        :return: the composed conversion string
        """
        return (
            f"{column} = CONVERT(CAST(CONVERT({column} "
            "USING latin1) as BINARY) USING utf8)"
        )

    def _convert_Config_to_utf8(self) -> Any:
        """Migrate the Config Value and Description to utf8."""
        cmd = "Update Config Set {}, {} ;".format(
            self._convert("Config.Description"),
            self._convert("Config.Value"),
        )
        return self._execute(cmd)

    def _convert_Token_to_utf8(self) -> Any:
        """Migrate the Token Description and LinOtpTokenInfo to utf8."""
        cmd = "Update Token Set {}, {} ;".format(
            self._convert("Token.LinOtpTokenDesc"),
            self._convert("Token.LinOtpTokenInfo"),
        )
        return self._execute(cmd)

    def _convert_ImportedUser_to_utf8(self) -> Any:
        """Migrate Username, Surname, Givenname and Email of imported_user to utf8."""
        cmd = "Update imported_user Set {}, {}, {}, {} ;".format(
            self._convert("imported_user.username"),
            self._convert("imported_user.surname"),
            self._convert("imported_user.givenname"),
            self._convert("imported_user.email"),
        )
        return self._execute(cmd)

    def migrate_data(self, tables: list) -> None:
        """Worker for the data migration.

        :param tables: list of tables where the data should be converted to utf8
        """
        tables = [t.lower() for t in tables]
        if "config" in tables:
            self._convert_Config_to_utf8()
        if "token" in tables:
            self._convert_Token_to_utf8()
        if "imported_user" in tables:
            self._convert_ImportedUser_to_utf8()


# ------------------------------------------------------------------------- --

# entry point for calling db migration


def run_data_model_migration(engine: Engine) -> str:
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


class Migration:
    """Migration class.

    - support the the db migration with a chain of db migration steps
      where each step is defined as class method according to the requested
      target version

    """

    # model version key in the config table

    db_model_key = "linotp.sql_data_model_version"

    # define the chain of migration steps starting with the not existing one
    #
    migration_steps = [
        None,
        "2.9.1.0",
        "2.10.1.0",
        "2.12.0.0",
        "3.0.0.0",
        "3.1.0.0",
        "3.2.0.0",
        "3.2.2.0",
        "3.2.3.0",
        "4.0.0.0",
    ]
    #!! the migration number should be the same as the linotp release number /
    # debian release number !!
    #
    # Background:
    #  the migration steps names are evaluated and used in the debian
    #  dbcommon-config to trigger database migration: dbcommon-config expects
    #  for every migration step an update script with a name same as its
    #  belonging release. These names are compared the current installed
    #  version and the upcomming debian package version and every update script
    # (with this version number) will be executed upfront to the installation.
    #
    # With linotp we need only one file with the current release name as all
    # migration up to the current version are done within the
    # 'linotp init database' command.

    def __init__(self, engine: Engine):
        """Class init.

        - preserve the database handle / engine
        """
        self.engine = engine
        self.current_version = None

    @staticmethod
    def _query_db_model_version() -> model.Config:
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

        return (
            model.Config.query.filter(model.Config.Key == "linotp.Config").first()
            is None
        )

    def get_current_version(self) -> str | None:
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

    def set_version(self, version: str) -> None:
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

        model.db.session.add(config_entry)  # pylint: disable=E1101

    def migrate(
        self,
        from_version: str | None = None,
        to_version: str | None = None,
    ) -> str | None:
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

        # ----------------------------------------------------------------- --

        # no migration for new database:
        #  if this is a new database, we don't need to run a migration
        #  the status untouched is determined by looking for the linotp.config
        #  time stamp database entry, which is written on every update

        if self.is_db_untouched():
            log.info("Fresh database - no migration required!")
            return to_version

        # ----------------------------------------------------------------- --

        active = False

        for next_version in self.migration_steps:
            if next_version and active:
                # --------------------------------------------------------- --

                # get the function pointer to the set version

                exec_version = next_version.replace(".", "_")
                function_name = f"migrate_{exec_version}"

                if not hasattr(self, function_name):
                    log.error("unknown migration function %r", function_name)
                    msg = f"unknown migration to {next_version!r}"
                    raise Exception(msg)

                migration_step = getattr(self, function_name)

                # --------------------------------------------------------- --

                # execute the migration step

                try:
                    migration_step()

                except Exception as exx:
                    log.error(
                        "Failed to upgrade database during migration step: %r",
                        function_name,
                    )
                    log.exception(str(exx))
                    model.db.session.rollback()  # pylint: disable=E1101
                    raise exx

            if next_version == from_version:
                active = True

            if next_version == to_version:
                break

        return to_version

    # --------------------------------------------------------------------- --

    # migration towards 2.9.1

    def migrate_2_9_1_0(self) -> None:
        """Run the migration for bigger sized challenge column."""

        challenge_table = "challenges"

        # add new bigger challenge column
        column = sa.Column("lchallenge", sa.types.Unicode(2000))

        if not has_column(self.engine, challenge_table, column):
            add_column(self.engine, challenge_table, column)

        # add column to refer to the parent transaction
        column = sa.Column("ptransid", sa.types.Unicode(64), index=True)

        if not has_column(self.engine, challenge_table, column):
            add_column(self.engine, challenge_table, column)
            add_index(self.engine, challenge_table, column)

    # --------------------------------------------------------------------- --

    # migration towards 2.10.1

    def migrate_2_10_1_0(self) -> None:
        """Run the migration to blob challenge and data column."""

        challenge_table = "challenges"

        # add new blob challenge column
        bchallenges = sa.Column("bchallenge", sa.types.LargeBinary())

        if not has_column(self.engine, challenge_table, bchallenges):
            add_column(self.engine, challenge_table, bchallenges)

        # add new blob data column
        bdata = sa.Column("bdata", sa.types.LargeBinary())

        if not has_column(self.engine, challenge_table, bdata):
            add_column(self.engine, challenge_table, bdata)

    # migration towards 2.12.

    def migrate_2_12_0_0(self) -> None:
        """Run the migration for token to add the time stamps.

        time stamps are: created, accessed and verified
        """

        token_table = "Token"

        # add created column to tokens
        created = sa.Column("LinOtpCreationDate", sa.types.DateTime, index=True)

        if not has_column(self.engine, token_table, created):
            add_column(self.engine, token_table, created)
            add_index(self.engine, token_table, created)

        # add verified column to tokens
        verified = sa.Column("LinOtpLastAuthSuccess", sa.types.DateTime, index=True)

        if not has_column(self.engine, token_table, verified):
            add_column(self.engine, token_table, verified)
            add_index(self.engine, token_table, verified)

        # add accessed column to tokens
        accessed = sa.Column("LinOtpLastAuthMatch", sa.types.DateTime, index=True)

        if not has_column(self.engine, token_table, accessed):
            add_column(self.engine, token_table, accessed)
            add_index(self.engine, token_table, accessed)

    # migration towards 3.0

    def migrate_3_0_0_0(self) -> None:
        """Migrate to linotp3 - to python3+mysql.

        The major challenge for the linotp3 migration is the migration from
        python2+mysql where the mysql driver was using latin1 encoded data,
        though the database might already support utf8.

        Thus we can exclude all fresh created and non-mysql databases
        """

        if self.is_db_untouched():
            log.info("Fresh database - no migration required!")
            return

        # ----------------------------------------------------------------- --

        # with LinOTP 3.0.0 we changed the audit signing method
        # making signatures of older entries invalid.
        # We log a warning to suggest manual deletion of old entries.
        from linotp.lib.audit.base import getAudit

        audit_obj = getAudit()
        total_audit_entries = audit_obj.getTotal({})
        if total_audit_entries > 0:
            log.info(
                "You have audit log entries from LinOTP 2.x. "
                "Their signatures will be invalid from LinOTP 3.0.0 on. "
                "We suggest you to run TRUNCATE on the audit database table."
            )

        # ----------------------------------------------------------------- --

        if not self.engine.url.drivername.startswith("mysql"):
            log.info(
                "Non mysql databases %r - no migration required.",
                self.engine.url.drivername,
            )
            return

        # ----------------------------------------------------------------- --

        # MYSQL Schema and Data Migration:
        #
        # In case of pre buster db (or restored by a backup), the tabel schema
        # is defined with charset latin1. Thus the schema must be updated first
        # othewise the data migration will fail.
        #
        # Which tables are converted is reported by the schema migration.
        # If no table was converted, we have to assume that the mysql db was
        # created newly (e.g. on buster) where this is done with charset=utf8.
        #
        # In case of a newly (buster) e.g. linotp2 created db, we cannot imply
        # that the data migration has to be done, we only can suggest this.

        log.info("Starting mysql migration")

        # before we adjust the schema, we have to close former sessions,
        # otherwise we would run into a database lock

        model.db.session.close()

        # now we can run the schema migration

        mysql_mig = MYSQL_Migration(self.engine)
        migrated_tables = mysql_mig.migrate_schema()
        mysql_mig.migrate_data(migrated_tables)

        if not migrated_tables:
            config_entry = model.Config(Key="utf8_conversion", Value="suggested")
            model.db.session.add(config_entry)

            log.warning(
                "Database conversion step suggested!\n"
                "Please run command:\n"
                " linotp admin fix-db-encoding"
            )

    def iso8859_to_utf8_conversion(self) -> tuple[bool, str]:
        """
        Migrate all User (only Username, Surname, Givenname and Email),
        Config and Token entries from latin1 to utf-8,

        but only if the label 'utf8_conversion':'suggested' is set

        conditions for this lable are (s.o.):
        - if the database is not created with this version
        - is it a mysql database

        :return: a tuple of bool and detail message
        """

        if (
            model.Config.query.filter(
                model.Config.Key == "linotp.utf8_conversion"
            ).first()
            is None
        ):
            return True, "No latin1 to utf8 conversion suggested!"

        log.info("Starting data convertion")

        try:
            mysql_mig = MYSQL_Migration(self.engine)
            mysql_mig.migrate_data(["Config", "Token", "imported_user"])

        except OperationalError as exx:
            log.info("Failed to run convertion: %r", exx)
            return False, f"Failed to run convertion: {exx!r}"

        finally:
            # in any case, we remove the conversion suggestion label

            model.Config.query.filter(
                model.Config.Key == "linotp.utf8_conversion"
            ).delete()

        return True, "User, Config and Token data converted to utf-8."

    def migrate_3_1_0_0(self) -> tuple[bool, str]:
        """Migrate the encrpyted data to pkcs7 padding.

        this requires to
        1. decrypt data and extract & unpadd the data with the old format
        2. padd and encrypt data with the new padding format

        This has to be done for the tokens and for the encrypted config values
        """

        from linotp.lib.security.default import (
            TOKEN_KEY,
            DefaultSecurityModule,
        )

        class MigrationSecurityModule(DefaultSecurityModule):
            """Migration helper class, which contains the old padding.

            during migration the unpadd method of the DefaultSecurity
            module is replaced with the old one to decrypt the old data
            representation.
            """

            @staticmethod
            def old_unpadd_data(output: bytes) -> bytes:
                eof = len(output) - 1

                if eof == -1:
                    msg = "invalid encoded secret!"
                    raise Exception(msg)

                while output[eof] == 0x00:
                    eof -= 1

                if not (output[eof - 1] == 0x01 and output[eof] == 0x02):
                    msg = "invalid encoded secret!"
                    raise Exception(msg)

                return output[: eof - 1]

            @staticmethod
            def old_padd_data(input_data: bytes) -> bytes:
                data = b"\x01\x02"
                padding = (16 - len(input_data + data) % 16) % 16
                return input_data + data + padding * b"\0"

        # ----------------------------------------------------------------- --

        # For re-encryption we get from the security provider the current
        # security module which we can use to run the decrypt and encrypt
        # methods

        sec_provider = current_app.security_provider
        sec_module = sec_provider.security_modules[sec_provider.activeOne]

        if not isinstance(sec_module, DefaultSecurityModule):
            log.info(
                "Padding migration is only required for the default security module"
            )
            return True, ("Migration for non default security module not required!")

        # ----------------------------------------------------------------- --

        # for the decryption the unpadding method is overwritten with the old
        # padding algorithm

        sec_module.unpadd_data = MigrationSecurityModule.old_unpadd_data

        # ----------------------------------------------------------------- --

        # re-encrypt all encrypted config table entries

        log.info("start to re-encrypt the config entries")

        entry_counter = 0

        for entry in model.Config.query.all():
            if entry.Type not in ["encrypted_data", "password"]:
                continue

            try:
                value = sec_module.decryptPassword(entry.Value).decode("utf-8")

                entry.Value = sec_module.encryptPassword(value.encode("utf-8"))

                # Change the type to `encrypted_data` since type `password` is used equivalently
                # and thus can be unified
                entry.Type = "encrypted_data"

                model.db.session.add(entry)

                log.info("%r re encrypted", entry.Key)

                entry_counter += 1

            except Exception as exx:
                log.error("Unable to re-encrypt %r: %r", entry.Key, exx)

        # ----------------------------------------------------------------- --

        # re-encrypt all tokens

        log.info("start to re-encrypt the tokens")

        token_counter = 0

        for token in model.Token.query.all():
            iv = binascii.unhexlify(token.LinOtpKeyIV)

            # ------------------------------------------------------------- --

            # special treatment of the new pw token
            # the new pw Tokenwe uses the standard password lib to deal with
            # the hashed passwords. The identifier for this is the
            # iv == b':1:' and thus LinOtpKeyEnc contains the hashed password.
            # So we have nothing to do here and just can continue

            if iv == b":1:" and token.LinOtpTokenType == "pw":
                continue

            # ------------------------------------------------------------- --

            # special treatment for the qr and push tokens.
            # Since these tokens do not have an EncKey we don't re-encrypt them.
            # Otherwise migration would fail, because token.LinOtpKeyEnc is None

            if token.LinOtpTokenType in ["qr", "push"]:
                continue

            if not token.LinOtpKeyEnc:
                continue
            # ------------------------------------------------------------- --

            encrypted_value = binascii.unhexlify(token.LinOtpKeyEnc)
            _enc = binascii.hexlify(encrypted_value)

            value = sec_module.decrypt(value=encrypted_value, iv=iv, id=TOKEN_KEY)

            new_encrypted_value = sec_module.encrypt(data=value, iv=iv, id=TOKEN_KEY)

            token.LinOtpKeyEnc = binascii.hexlify(new_encrypted_value).decode("utf8")

            model.db.session.add(token)

            token_counter += 1

        # ----------------------------------------------------------------- --

        # final reset the unpadding and return a status message

        sec_module.unpadd_data = DefaultSecurityModule.unpadd_data

        return True, (
            f"re-encryption completed! {token_counter!r} tokens and {entry_counter!r} config entries "
            "migrated"
        )

    def migrate_3_2_0_0(self):
        """Migrate to 3.2 creates the internal (managed) admin resolver"""

        admin_resolver_name = current_app.config["ADMIN_RESOLVER_NAME"]
        model.create_admin_resolver(admin_resolver_name=admin_resolver_name)

        admin_realm_name = current_app.config["ADMIN_REALM_NAME"]
        model.create_admin_realm(admin_realm_name, admin_resolver_name)

        return True, (
            f"internal (managed) admin resolver {admin_resolver_name} created"
        )

    def migrate_3_2_2_0(self):
        """Migration to 3.2.2 drops all challenges"""

        model.Challenge.query.delete()

        return True, ("Migration to 3.2.2 - all challenge entries are deleted.")

    def migrate_3_2_3_0(self):
        """
        Migration to 3.2.3 - dummy migration step

        which is required to trigger debian dbconfig upgrade
        """

        return True, ("Migration to 3.2.3 - to trigger debian dbconfig upgrade")

    def migrate_4_0_0_0(self):
        """
        Migration to 4.0.0 - remove OATHTokenSupport config item and update
        webprovisionGOOGLE and webprovisionGOOGLEtime policies to enrollHMAC and enrollTOTP.
        """
        # Remove OATHTokenSupport policy
        model.Config.query.filter(model.Config.Key == "linotp.OATHTokenSupport").delete(
            synchronize_session=False
        )

        log.info("OATHTokenSupport policy removed")

        # Migrate webprovisionGOOGLE and webprovisionGOOGLEtime policies
        policy_entries = model.Config.query.filter(
            sa.and_(
                model.Config.Key.like("linotp.Policy.%.action"),
                sa.or_(
                    model.Config.Value.contains("webprovisionGOOGLE"),
                    model.Config.Value.contains("webprovisionGOOGLEtime"),
                ),
            )
        ).all()

        for entry in policy_entries:
            # Updating policy value
            policy_actions = _parse_action(entry.Value)
            new_value, changed = Migration_4_0_0_0.rename_webprovision_google_policies(
                list(policy_actions)
            )
            if changed:
                log.info(
                    "Updating policy value %r from %r to %r",
                    entry.Key,
                    entry.Value,
                    new_value,
                )
                entry.Value = new_value
                model.db.session.add(entry)

        return True, (
            "Migration to 4.0.0 - webprovision policies are updated and OATHTokenSupport config item is removed"
        )


def _parse_action(action_value):
    # to avoid circular import import lazily parse_action
    # parse_action is used here in migrate script and internally in policy module
    # creating separate module only for it would be overkill at least for now
    from linotp.lib.policy.util import parse_action

    return parse_action(action_value)


class Migration_4_0_0_0:
    """This static class is a namespace for all migration functions
    that are related to the migration to 4.0.0.0
    """

    @staticmethod
    def rename_webprovision_google_policies(
        entry_values: list[tuple[str, str | int | bool]],
    ) -> tuple[str | None, bool]:
        """
        Map webprovisionGOOGLE and webprovisionGOOGLEtime policies to enrollHMAC and enrollTOTP.
        This function builds new policy value string.
        Duplicate policies are removed and formatting could be changed !

        :param entry_values: List of tuples containing policy name and value.
        :return: The updated entry value with mapped policies and a boolean indicating if the value was changed.
        """
        # If value doesnt contain webprovisionGOOGLE or webprovisionGOOGLEtime
        # we dont change string

        POLICY_MAPPINGS = {
            "webprovisionGOOGLE": "enrollHMAC",
            "webprovisionGOOGLEtime": "enrollTOTP",
        }

        if not any(name in POLICY_MAPPINGS for name, _ in entry_values):
            return None, False

        changed_policies = []
        seen_keys = set()
        for key, value in entry_values:
            mapped_policy_key = POLICY_MAPPINGS.get(key.strip(), key)
            if mapped_policy_key and mapped_policy_key not in seen_keys:
                changed_policies.append((mapped_policy_key, value))
                seen_keys.add(mapped_policy_key)

        def format_single_action(
            policy_action: tuple[str, str | int | bool],
        ) -> str:
            key, value = policy_action
            # check is value is boolean and True
            if isinstance(value, bool) and value:
                return key
            if isinstance(value, str) and value:
                return f'{key}="{value}"'
            return f"{key}={value}"

        result = ", ".join(
            format_single_action(policy_action) for policy_action in changed_policies
        )
        return result, True
