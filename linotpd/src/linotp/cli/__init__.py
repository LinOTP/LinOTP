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

from datetime import datetime
from flask import current_app
from flask.cli import main as flask_main
from flask.cli import AppGroup
from flask.cli import with_appcontext
from linotp.lib.tools.enckey import create_secret_key
from linotp.lib.tools.sql_janitor import SQLJanitor


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
              help='Overwrite encKey file if it exists already.')
def init_enc_key(force):
    """Creates a LinOTP secret file to encrypt and decrypt values in database

    The key file is used via the default security provider to encrypt
    token seeds, configuration values...
    If --force or -f is set and the encKey file exists already, it
    will be overwritten.
    """

    filename = current_app.config["SECRET_FILE"]

    if os.path.exists(filename):
        if force:
            click.echo(
                f"The enc-key file, {filename}, already exists.\n"
                "Overwriting an existing enc-key might make existing data in "
                "the database inaccessible.\n"
                "THAT WOULD BE VERY BAD.")
            answer = click.prompt(
                "Overwrite the existing enc-key", default="no",
                type=click.Choice(['yes', 'no'], case_sensitive=True),
                show_choices=True)
            if answer == 'yes':
                backup_filename = filename + '.' + datetime.now().isoformat(timespec='seconds')
                try:
                    os.replace(filename, backup_filename)
                    click.echo(f"Moved existing enc-key file to {backup_filename}")
                except IOError as ex:
                    click.echo(f"Error moving existing enc-key file to {backup_filename}: {ex!s}",
                            err=True)
                    sys.exit(1)
                try:
                    create_secret_key(filename)
                    click.echo(f"Wrote enc-key to {filename}", err=True)
                except IOError as ex:
                    click.echo(f"Error writing enc-key to {filename}: {ex!s}", err=True)
            else:
                click.echo(f"Not overwriting existing enc-key in {filename}", err=True)
    else:
        try:
            create_secret_key(filename)
            click.echo(f'Wrote enc-key to {filename}')
        except IOError as ex:
            click.echo(f'Error writing enc-key to {filename}: {ex!s}',
                       err=True)



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
        if not(0 <= min < max):
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
      
