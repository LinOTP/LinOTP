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

"""Entry point for LinOTP CLI.

The `main()` function in this file is installed as a console entry point
in `setup.py()`, so that the shell command `linotp` calls that function.
We use this to ensure that Flask is initialised with the correct value
for `FLASK_APP`.

"""

import os
import click
import sys

from subprocess import call

from flask import current_app
from flask.cli import main as flask_main
from flask.cli import AppGroup
from flask.cli import with_appcontext
from linotp.lib.tools.enckey import create_secret_key
from linotp.lib.tools.sql_janitor import SQLJanitor

from linotp.model.backup import backup_audit_tables
from linotp.model.backup import backup_database_tables
from linotp.model.backup import list_database_backups
from linotp.model.backup import list_audit_backups
from linotp.model.backup import restore_database_tables
from linotp.model.backup import restore_audit_table
from linotp.model.backup import restore_legacy_database

FLASK_APP_DEFAULT = "linotp.app"   # Contains default `create_app()` factory
FLASK_ENV_DEFAULT = "development"  # Default Flask environment, for debugging


def main():
    """Main CLI entry point for LinOTP. All the heavy lifting is delegated
    to Flask.
    """

    os.environ["FLASK_APP"] = FLASK_APP_DEFAULT
    if "FLASK_ENV" not in os.environ:
        os.environ["FLASK_ENV"] = FLASK_ENV_DEFAULT
    flask_main()


init_cmds = AppGroup('init')

@init_cmds.command('enc-key',
                   help='Generate aes key for encryption and decryption')
@click.option('--force', '-f', is_flag=True,
              help='Override encKey file if exits already.')
def init_enc_key(force):
    """Creates a LinOTP secret file to encrypt and decrypt values in database

    The key file is used via the default security provider to encrypt
    token seeds, configuration values...
    If --force or -f is set and the encKey file exists already, it
    will be overwritten.
    """

    filename = current_app.config["SECRET_FILE"]
    if os.path.exists(filename) and not force:
        click.echo(f'Not overwriting existing enc-key in {filename}', err=True)
    else:
        try:
            create_secret_key(filename)
            click.echo(f'Wrote enc-key to {filename}', err=True)
        except IOError as ex:
            click.echo(f'Error writing enc-key to {filename}: {ex!s}',
                       err=True)

# -------------------------------------------------------------------------- --

# backup commands

backup_cmds = AppGroup('backup')

@backup_cmds.command('database', help='create a backup of the database tables')
def backup_database():
    """Create backup file for your database tables
    """

    current_app.logger.info("Backup database ...")

    exit_code = backup_database_tables(current_app)

    current_app.logger.info("finished")

    sys.exit(exit_code)

@backup_cmds.command('audit', help='create a backup of the audit database')
def backup_audit():
    """Create backup file for your audit database table
    """

    current_app.logger.info("Backup database ...")

    exit_code = backup_audit_tables(current_app)

    current_app.logger.info("finished")

    sys.exit(exit_code)

# -------------------------------------------------------------------------- --

# restore commands

restore_cmds = AppGroup('restore')

@restore_cmds.command('database',
                      help='restore a backup of the database tables')
@click.option('--file', help='name of the backup file')
@click.option('--date', help='restore the backup from a given date.'
              '"date" must be in format "%y%m%d%H%M"')
@click.option('--table', help='restore the backup of a table - '
              'table must be one of "Config", "Token", "Audit"')
@click.option('--list',  is_flag=True,
              help='show available backup files that can be restored')
def restore_database(file=None, date=None, table=None, list=False):
    """ restore a database backup

    @param file - the backup file name, could be absolute or relative
    @param date - select a backup for restore by date
    @param table - allows to restore only one database table
    @param list - list all available database backups
    """
    if list:

        current_app.logger.info("Available backup files for restore")

        exit_code = list_database_backups(current_app)

        current_app.logger.info("finished")

        sys.exit(exit_code)

    current_app.logger.info("Restoring database ...")

    exit_code = restore_database_tables(current_app, file, date, table)

    current_app.logger.info("finished")

    sys.exit(exit_code)

@restore_cmds.command('audit',
                      help='restore a backup of the database tables')
@click.option('--file', help='name of the backup file')
@click.option('--date', help='restore the backup from a given date.'
              '"date" must be in format "%y%m%d%H%M"')
@click.option('--list',  is_flag=True,
              help='show available backup files that can be restored')
def restore_audit(file=None, date=None, list=False):
    """restore an audit backup

    @param file - the backup file name, could be absolute or relative
    @param data - select a backup for restore by date
    @param list - list all available audit backups
    """
    if list:

        current_app.logger.info("Available audit backup files for restore")

        exit_code = list_audit_backups(current_app)

        current_app.logger.info("finished")

        sys.exit(exit_code)

    current_app.logger.info("Restoring audit ...")

    exit_code = restore_audit_table(current_app, filename=file, date=date)

    current_app.logger.info("finished")

    return sys.exit(exit_code)

@restore_cmds.command('legacy',
                      help='restore a legacy backup file (mysql)')
@click.option('--file', help='name of the backup file')
def restore_legacy(file):

    current_app.logger.info("Restoring legacy database ...")

    exit_code = restore_legacy_database(current_app, filename=file)

    current_app.logger.info("finished")

    sys.exit(exit_code)


@click.command('audit_janitor',
                help='Reduce the amount of audit log entries in the database')
@click.option('--max',
              default=10000,
              help='The maximum entries. If not given 10.000 as default is ' +
                   'assumed.')
@click.option('--min',
              default=5000,
              help='The minimum old remaining entries. If not given 5.000 ' +
                   'as default is assumed.')
@click.option('--exportdir', '-e',
               type=click.Path(exists=True, dir_okay=True),
               help='Defines the directory where the audit entries which ' +
               'are cleaned up are exported. A example filename would be: ' +
               'SQLData.yeah.month.day-max_id.csv')
@with_appcontext
def audit_janitor(max, min, exportdir):
    """This function removes old entries from the audit table.

    If more than max entries are in the audit table, older entries
    will be deleted so that only min entries remain in the table.
    This tool can decrypt the OTP Key stored in the LinOTP database. You need
    to pass the encrypted key, the IV and the filename of the encryption key.
    """

    try:
        if max <= min:
            click.echo('Error: max has to be greater than min.')
            sys.exit(1)

        sqljanitor = SQLJanitor(current_app, current_app.audit_obj.engine, export=exportdir)
        cleanup_infos = sqljanitor.cleanup(max, min)
        click.echo(f'{cleanup_infos["entries_in_audit"]} entries found in database.')
        if cleanup_infos['entries_deleted'] > 0:
            click.echo(
                f'{cleanup_infos["entries_in_audit"] - min} entries cleaned up. {min} ' +
                'entries left in database.\n'+
                f'Min: {min}, Max: {max}.')
            if cleanup_infos["export_filename"]:
                click.echo(f'Exported into {cleanup_infos["export_filename"]}')
            click.echo(f'Cleaning up took {cleanup_infos["time_taken"]} seconds')
        else:
            click.echo(
                f'Nothing cleaned up. {cleanup_infos["entries_in_audit"]} ' +
                f'entries in database.\n'+
                f'Min: {min}, Max: {max}.')

    except Exception as ex:
        click.echo(f'Error while cleanup up audit table: {ex!s}')
      
