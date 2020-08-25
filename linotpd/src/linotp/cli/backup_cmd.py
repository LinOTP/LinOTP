# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2020 arxes-Tolina
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
database backup implementation
"""

import os
import sys
import binascii
import click

from datetime import datetime

from flask import current_app
from sqlalchemy.ext.serializer import loads, dumps

from sqlalchemy import create_engine

from flask.cli import AppGroup

from linotp.model.meta import Session as session
from linotp.model import Config, Token, TokenRealm, Realm
from linotp.model import init_model, meta

from linotp.lib.audit.SQLAudit import AuditTable


TIME_FORMAT = '%Y-%m-%d_%H-%M'


ORM_Models = {
    'Config': Config,
    'Token': Token,
    'TokenRealm': TokenRealm,
    'Realm': Realm
    }

# -------------------------------------------------------------------------- --

# backup commands

backup_cmds = AppGroup('backup')


@backup_cmds.command('create', help='create a backup of the database tables')
def create_command():
    """Create backup file for your database tables
    """

    try:
        current_app.echo("Backup database ...", v=1)
        backup_database_tables()
        current_app.echo("finished", v=1)
    except Exception as exx:
        current_app.echo('Failed to backup: %r' % exx)
        sys.exit(1)


@backup_cmds.command('restore',
                     help='restore a backup of the database tables')
@click.option('--file', help='name of the backup file')
@click.option('--date', help='restore the backup from a given date.'
              '"date" must be in format "%s"' % TIME_FORMAT)
@click.option('--table', help='restore the backup of a table - '
              'table must be one of "Config", "Token", "Audit"')
def restore_command(file=None, date=None, table=None):
    """ restore a database backup

    @param file - the backup file name, could be absolute or relative
    @param date - select a backup for restore by date
    @param table - allows to restore only one database table
    """
    try:
        current_app.echo("Restoring database ...", v=1)
        restore_database_tables(file, date, table)
        current_app.echo("finished", v=1)
    except Exception as exx:
        current_app.echo('Failed to restore: %r' % exx)
        sys.exit(1)


@backup_cmds.command('list',
                     help='restore a backup of the database tables')
def list_command():
    """ list available database backups."""
    try:
        current_app.echo("Available backup files for restore", v=1)
        for backup_date, backup_file in list_database_backups():
            current_app.echo(f'{backup_date} {backup_file}', err=False)
        current_app.echo("finished", v=1)
    except Exception as exx:
        current_app.echo('Failed to list backup files: %r' % exx)
        sys.exit(1)


# -------------------------------------------------------------------------- --

# backend implementation

def backup_database_tables() -> int:
    """
    use the sqlalchemy serializer to dump the database mapped objects
    """
    app = current_app

    backup_filename_template = "linotp_backup_%s.sqldb"

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # ---------------------------------------------------------------------- --

    # if audit is shared, it belongs to the same database, thus we make as
    # well an backup of the audit

    backup_classes = ORM_Models

    audit_db = app.config["AUDIT_DATABASE_URI"]
    if audit_db == 'SHARED':
        backup_classes['AuditTable'] = AuditTable

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    engine = create_engine(sql_uri)

    init_model(engine)

    app.echo("extracting data from: %r:%r" %
             (engine.url.drivername, engine.url.database), v=1)

    # ---------------------------------------------------------------------- --

    # setup the backup location

    backup_dir = current_app.config["BACKUP_DIR"]
    os.makedirs(backup_dir, exist_ok=True)

    # ---------------------------------------------------------------------- --

    # determin the datetime extension

    now = datetime.now()
    now_str = now.strftime(TIME_FORMAT)

    # ---------------------------------------------------------------------- --

    # run the db serialisation and dump / pickle the data

    backup_filename = os.path.join(
        backup_dir, backup_filename_template % now_str)

    app.echo("creating backup file: %s" % backup_filename, v=1)

    with open(backup_filename, "w") as backup_file:

        for name, model_class in backup_classes.items():

            app.echo("saving %s" % name, v=1)

            backup_file.write("--- BEGIN %s\n" % name)

            data_query = session.query(model_class)

            pb_file = (None if app.echo.verbosity > 1
                       else open("/dev/null", "w"))  # None => stdout

            with click.progressbar(
                    data_query.all(), label=name, file=pb_file) as all_data:
                for data in all_data:
                    backup_file.write(binascii.hexlify(dumps(data))
                                      .decode('utf-8'))

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

    filename_template = 'linotp_backup_'

    # ---------------------------------------------------------------------- --

    # setup the backup location

    backup_dir = app.config["BACKUP_DIR"]

    if not os.path.exists(backup_dir):
        app.echo("no backup directory found: %s" % backup_dir, v=2)
        return

    # ---------------------------------------------------------------------- --

    # lookup for all files in the directory that match the template

    for backup_file in os.listdir(backup_dir):

        # backup files match the 'template' + "%s.sqldb" format

        if (backup_file.startswith(filename_template)
                and backup_file.endswith('.sqldb')):

            backup_date, _, _ext = backup_file[
                len(filename_template):].rpartition('.')

            yield backup_date, backup_file


# -------------------------------------------------------------------------- --

# restore

def _get_restore_filename(
        template: str, filename: str = None, date: str = None) -> str or None:
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
        backup_filename = os.path.join(
            backup_dir, template % date)

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
            "failed to restore - no date or file name parameter provided",
            v=1)
        raise ValueError("no date or file name parameter provided!")

    # ---------------------------------------------------------------------- --

    # verify that the file to restore from exists

    if not os.path.isfile(backup_filename):

        app.echo(
            "failed to restore %s - not found or not accessible"
            % backup_filename)
        raise FileNotFoundError("failed to restore %s - not found or not"
                                " accessible" % backup_filename)

    return backup_filename


def restore_database_tables(
        filename: str = None, date: str = None, table: str = None) -> int:
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
    if audit_uri == 'SHARED':
        restore_names.append('AuditTable')

    # ---------------------------------------------------------------------- --

    # determine which table should be restored specified by the table parameter
    #  If the token table should be restored we require to restore Realm and
    #  TokenRealm as well, as the have an n:m relationship

    if table:

        if table.lower() == 'config':
            restore_names = ['Config']

        elif table.lower() == 'audit':
            restore_names = ['AuditTable']

        elif table.lower() == 'token':
            restore_names = ['Token', 'TokenRealm', 'Realm']

        else:
            app.echo(
                f"selected table {table} is not in the set "
                "of supported tables",
                v=1)
            raise ValueError(f"selected table {table} is not in the set "
                             "of supported tables")

    # ---------------------------------------------------------------------- --

    # determine the backup file for the database restore

    backup_filename = _get_restore_filename(
                        "linotp_backup_%s.sqldb", filename, date)

    # ---------------------------------------------------------------------- --

    # get the database uri for the linotp database

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    engine = create_engine(sql_uri)

    init_model(engine)

    # ---------------------------------------------------------------------- --

    # restore the sqlalchemy dump from file

    with open(backup_filename, "r") as backup_file:

        for line in backup_file:
            line = line.strip()

            if line.startswith('--- END '):
                name = None

            elif line.startswith('--- BEGIN '):
                name = line[len('--- BEGIN '):]

            elif line and name in restore_names:

                # unhexlify the serialized data first

                data = binascii.unhexlify(line.encode('utf-8'))

                # use sqlalchemy loads to de-serialize the data objects

                restore_query = loads(data, meta.metadata, session)

                # merge the objects into the current session

                session.merge(restore_query)

                app.echo("restoring %r" % name, v=1)

    # finally commit all de-serialized objects

    session.commit()
