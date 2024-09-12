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
"""MySQL-specific database backup implementation.

The difference between this and the `dbsnapshot` command is that
`dbsnapshot` uses the SQLAlchemy object-dump facility while this
implementation uses the MySQL-specific `mysqldump` shell command.

This means that `backup` can be used to make backups that can be restored
on MySQL-based LinOTP instances of different versions, while `dbsnapshot`
can be used to make backups that are independent of the actual database
engine but can run into issues as the definitions of LinOTP objects evolve.

In other words, `backup` is probably more useful in daily life (as long
as MySQL is your thing) but `dbsnapshot` lets you migrate your LinOTP
instance from MySQL to PostgreSQL (for example).
"""

import os
import subprocess
import sys
from pathlib import Path

import click
from sqlalchemy import create_engine

from flask import current_app
from flask.cli import AppGroup

from . import get_backup_filename

# -------------------------------------------------------------------------- --

# backup legacy commands: restore (+ backup == to be implemented and tested)

backup_cmds = AppGroup("backup", help="Manage database-specific backups")


@backup_cmds.command("restore", help="Restore a MySQL backup file.")
@click.option("--file", help="name of the MySQL backup file")
def restore_mysql_command(file):
    """Restore MySQL backups."""
    try:
        current_app.echo("Restoring legacy database ...", v=1)
        restore_mysql_database(filename=file)
        current_app.echo("Finished", v=1)
    except Exception as exx:
        current_app.echo(f"Failed to restore MySQL backup: {exx!r}")
        sys.exit(1)


@backup_cmds.command("create", help="Create a backup of a MySQL database.")
def backup_mysql_command():
    """Backup MySQL database."""
    try:
        current_app.echo("Backup MySQL database ...", v=1)
        backup_mysql_database()
        current_app.echo("Finished", v=1)
    except Exception as exx:
        current_app.echo(f"Failed to create MySQL backup: {exx!r}")
        sys.exit(1)


# -------------------------------------------------------------------------- --

# backend implementation


def backup_mysql_database():
    """backup the mysql database via mysqldump

    similar to the original bash script, thus
    - using the same time-stamp format
    - backup of the enckey
    """
    app = current_app

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    sql_uri = app.config["DATABASE_URI"]

    engine = create_engine(sql_uri)

    if "mysql" not in engine.url.drivername:
        app.echo(
            "MySQL backup file can only be created from a"
            " MySQL database. current database driver "
            f"is {engine.url.drivername!r}"
        )
        raise click.Abort()

    # ---------------------------------------------------------------------- --

    # Setup backup_dir

    filename = get_backup_filename("linotp_backup_%s.sql")
    backup_dir = Path(current_app.config["BACKUP_DIR"])
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_filename = os.path.join(backup_dir, filename)

    # ---------------------------------------------------------------------- --

    # determine the mysql command parameters

    command = [
        "mysqldump",
        f"--user={engine.url.username}",
        f"--password={engine.url.password_original}",
        f"--port={engine.url.port or 3306}",
        f"--host={engine.url.host}",
        f"--result-file={backup_filename}",
        engine.url.database,
    ]

    # ---------------------------------------------------------------------- --

    # run the backup in subprocess

    app.echo(f"MySQL backup {backup_filename!r}", v=1)

    cmd = " ".join(command)
    result = subprocess.call(cmd, shell=True)  # nosec

    if result != 0 or not os.path.isfile(backup_filename):
        app.echo(f"Failed to create MySQL backup file: {result!r}")
        raise click.Abort()

    app.echo(f"MySQL backup file {backup_filename!s} created!", v=1)


def restore_mysql_database(filename: str):
    """
    restore the mysql dump of a former linotp tools backup

    @param file: backup file name - absolute filename
    """
    app = current_app

    backup_filename = os.path.abspath(filename.strip())

    if not os.path.isfile(backup_filename):
        app.echo(f"MySQL backup file {filename!r} cannot be accessed.", v=1)
        raise click.Abort()

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    sql_uri = app.config["DATABASE_URI"]

    engine = create_engine(sql_uri)

    if "mysql" not in engine.url.drivername:
        app.echo(
            "MySQL backup file can only be restored to a "
            "MySQL database. Current database driver "
            f"is {engine.url.drivername!r}"
        )
        raise click.Abort()

    # ---------------------------------------------------------------------- --

    # determine the mysql command parameters

    command = [
        "mysql",
        f"--user={engine.url.username}",
        f"--password={engine.url.password_original}",
        f"--host={engine.url.host}",
        f"--port={engine.url.port or 3306}",
        "-D",
        engine.url.database,
    ]

    # ---------------------------------------------------------------------- --

    # run the restore in subprocess

    msg = ""

    app.echo(f"Restoring MySQL backup {backup_filename!r}", v=1)

    with open(backup_filename, "r") as backup_file:
        result = subprocess.run(
            command, stdin=backup_file, capture_output=True
        )

        if result.returncode != 0:
            app.echo(
                "Failed to restore MySQL backup file: "
                f"{result.stderr.decode('utf-8')!s}"
            )
            raise click.Abort()

        msg = result.stdout.decode("utf-8")

    app.echo(f"MySQL backup file restored: {msg!s}", v=1)
