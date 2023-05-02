# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
Database "snapshot" backup implementation.

The difference between this and the `backup` command in `mysql_cmd.py` is
that `backup` uses the MySQL-specific `mysqldump` shell command, while
this implementation uses SQLAlchemy's object-dump facilities.

This means that `backup` can be used to make backups that can be restored
on MySQL-based LinOTP instances of different versions, while `dbsnapshot`
can be used to make backups that are independent of the actual database
engine but can run into issues as the definitions of LinOTP objects evolve.

In other words, `backup` is probably more useful in daily life (as long
as MySQL is your thing) but `dbsnapshot` lets you migrate your LinOTP
instance from MySQL to PostgreSQL (for example).
"""

import binascii
import os
import sys

import click
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.serializer import dumps, loads

from flask import current_app
from flask.cli import AppGroup

from linotp.lib.audit.SQLAudit import AuditTable
from linotp.model.config import Config
from linotp.model.realm import Realm
from linotp.model.token import Token
from linotp.model.tokenRealm import TokenRealm

from . import get_backup_filename

TIME_FORMAT = "%Y-%m-%d_%H-%M"


ORM_Models = {
    "Config": Config,
    "Token": Token,
    "TokenRealm": TokenRealm,
    "Realm": Realm,
}

# -------------------------------------------------------------------------- --

# dbsnapshot commands

dbsnapshot_cmds = AppGroup(
    "dbsnapshot", help=("Manage system-independent database 'snapshots'")
)


@dbsnapshot_cmds.command(
    "create", help="Create a snapshot of the database tables."
)
def create_command():
    """Create backup file for your database tables"""

    try:
        current_app.echo("Backup database ...", v=1)
        backup_database_tables()
        current_app.echo("finished", v=1)
    except Exception as exx:
        current_app.echo("Failed to backup: %r" % exx)
        sys.exit(1)


@dbsnapshot_cmds.command(
    "restore", help="Restore a snapshot of the database tables."
)
@click.option("--file", help="Name of the snapshot file.")
@click.option(
    "--date",
    help=(
        "Restore a snapshot from a given date. "
        "'date' must be in format '%s'." % TIME_FORMAT
    ),
)
@click.option(
    "--table",
    type=click.Choice(["config", "token", "audit"], case_sensitive=False),
    help="Restore a specific table only.",
)
def restore_command(file=None, date=None, table=None):
    """restore a database snapshot

    @param file - the snapshot file name, could be absolute or relative
    @param date - select a snapshot to restore by date
    @param table - allows to restore only one database table
    """
    try:
        current_app.echo("Restoring snapshot ...", v=1)
        restore_database_tables(file, date, table)
        current_app.echo("Finished", v=1)
    except Exception as exx:
        current_app.echo(f"Failed to restore: {exx!r}")
        sys.exit(1)


@dbsnapshot_cmds.command(
    "list", help=("List available snapshots of the database tables.")
)
def list_command():
    """list available database snapshots."""
    try:
        current_app.echo("Available snapshots to restore", v=1)
        for backup_date, backup_file in list_database_backups():
            current_app.echo(f"{backup_date} {backup_file}", err=False)
        current_app.echo("Finished", v=1)
    except Exception as exx:
        current_app.echo("Failed to list snapshot files: {exx!r}")
        sys.exit(1)


# -------------------------------------------------------------------------- --

# backend implementation


def backup_database_tables() -> int:
    """
    use the sqlalchemy serializer to dump the database mapped objects
    """
    app = current_app

    backup_filename_template = "linotp_backup_%s.sqldb"

    # ---------------------------------------------------------------------- --

    # if audit is shared, it belongs to the same database, thus we make as
    # well an backup of the audit

    backup_classes = ORM_Models

    audit_db = app.config["AUDIT_DATABASE_URI"]
    if audit_db == "SHARED":
        backup_classes["AuditTable"] = AuditTable

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    db = SQLAlchemy(app)

    app.echo(
        "extracting data from: %r:%r"
        % (db.engine.url.drivername, db.engine.url.database),
        v=1,
    )

    # ---------------------------------------------------------------------- --

    # setup the backup location

    backup_dir = current_app.config["BACKUP_DIR"]
    os.makedirs(backup_dir, exist_ok=True)

    # ---------------------------------------------------------------------- --

    # run the db serialisation and dump / pickle the data

    filename = get_backup_filename(backup_filename_template)
    backup_filename = os.path.join(backup_dir, filename)

    app.echo("Creating backup file: %s" % backup_filename, v=1)

    with open(backup_filename, "w") as backup_file:
        for name, model_class in backup_classes.items():
            app.echo("Saving %s" % name, v=1)

            backup_file.write("--- BEGIN %s\n" % name)

            data_query = model_class.query

            pb_file = (
                None if app.echo.verbosity > 1 else open("/dev/null", "w")
            )  # None => stdout

            with click.progressbar(
                data_query.all(), label=name, file=pb_file
            ) as all_data:
                for data in all_data:
                    backup_file.write(
                        binascii.hexlify(dumps(data)).decode("utf-8")
                    )

                app.echo(".", v=2, nl=False)

            # final newline for detail
            app.echo("", v=2)

            backup_file.write("\n--- END %s\n" % name)


def list_database_backups() -> list:
    """
    find all backup files in the backup directory

    @return list of backup dates
    """
    app = current_app

    filename_template = "linotp_backup_"

    # ---------------------------------------------------------------------- --

    # setup the backup location

    backup_dir = app.config["BACKUP_DIR"]

    if not os.path.exists(backup_dir):
        app.echo("no backup directory found: %s" % backup_dir, v=2)
        return

    # ---------------------------------------------------------------------- --

    # lookup for all files in the directory that match the template

    for backup_file in os.listdir(backup_dir):
        # backup files match the "template" + "%s.sqldb" format

        if backup_file.startswith(filename_template) and backup_file.endswith(
            ".sqldb"
        ):
            backup_date, _, _ext = backup_file[
                len(filename_template) :
            ].rpartition(".")

            yield backup_date, backup_file


# -------------------------------------------------------------------------- --

# restore


def _get_restore_filename(
    template: str, filename: str = None, date: str = None
) -> str or None:
    """
    helper for restore, to determin a filename from a given date or file name

    @param template - the file name template to search for
    @param filename - the absolute or relative backup file name
    @param date - find a backup file by date
    @return the matching filename or None
    """
    app = current_app

    backup_filename = None
    backup_dir = app.config["BACKUP_DIR"]

    if date:
        backup_filename = os.path.join(backup_dir, template % date)

    elif filename:
        # check if file is absolute or relative to the backup directory

        if os.path.isfile(filename):
            backup_filename = filename
        else:
            backup_filename = os.path.join(backup_dir, filename)

    # ---------------------------------------------------------------------- --

    # no file or data parameter was provided

    if not filename and not date:
        app.echo(
            "failed to restore - no date or file name parameter provided", v=1
        )
        raise ValueError("no date or file name parameter provided!")

    # ---------------------------------------------------------------------- --

    # verify that the file to restore from exists

    if not os.path.isfile(backup_filename):
        app.echo(
            "Failed to restore %s - not found or not accessible"
            % backup_filename
        )
        raise FileNotFoundError(
            "failed to restore %s - not found or not"
            " accessible" % backup_filename
        )

    return backup_filename


def restore_database_tables(
    filename: str = None, date: str = None, table: str = None
) -> int:
    """
    restore the database tables from a file or for a given date
       optionally restore only one table

    @param filename - the absolute or relative backup file name
    @param date - find a backup file by date
    @param table - restore only one database table e.g. tokens
    """
    app = current_app

    restore_names = list(ORM_Models.keys())

    audit_uri = app.config["AUDIT_DATABASE_URI"]
    if audit_uri == "SHARED":
        restore_names.append("AuditTable")

    # ---------------------------------------------------------------------- --

    # determine which table should be restored specified by the table parameter
    #  If the token table should be restored we require to restore Realm and
    #  TokenRealm as well, as the have an n:m relationship

    if table:
        if table.lower() == "config":
            restore_names = ["Config"]

        elif table.lower() == "audit":
            restore_names = ["AuditTable"]

        elif table.lower() == "token":
            restore_names = ["Token", "TokenRealm", "Realm"]

        else:
            app.echo(
                f"selected table {table} is not in the set "
                "of supported tables",
                v=1,
            )
            raise ValueError(
                f"selected table {table} is not in the set "
                "of supported tables"
            )

    # ---------------------------------------------------------------------- --

    # determine the backup file for the database restore

    backup_filename = _get_restore_filename(
        "linotp_backup_%s.sqldb", filename, date
    )

    # ---------------------------------------------------------------------- --

    db = SQLAlchemy(app)

    # ---------------------------------------------------------------------- --

    # restore the sqlalchemy dump from file

    with open(backup_filename, "r") as backup_file:
        for line in backup_file:
            line = line.strip()

            if line.startswith("--- END "):
                name = None

            elif line.startswith("--- BEGIN "):
                name = line[len("--- BEGIN ") :]

            elif line and name in restore_names:
                # unhexlify the serialized data first

                data = binascii.unhexlify(line.encode("utf-8"))

                # use sqlalchemy loads to de-serialize the data objects

                restore_query = loads(data, db.metadata, db.session)

                # merge the objects into the current session

                db.session.merge(restore_query)

                app.echo("Restoring %r" % name, v=1)

    # finally commit all de-serialized objects

    db.session.commit()
