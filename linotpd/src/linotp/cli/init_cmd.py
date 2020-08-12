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

""" linotp init commands.

linotp init database
linotp init enc-key

"""

import sys
import os
import tempfile
import click

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from flask import current_app

from flask.cli import AppGroup
from flask.cli import with_appcontext

from linotp.model import init_model, meta         # FIXME: With Flask-SQLAlchemy
from linotp.model.migrate import run_data_model_migration
from linotp.defaults import set_defaults


KEY_COUNT = 3
KEY_LENGTH = 32
SECRET_FILE_PERMISSIONS = 0o400


# -------------------------------------------------------------------------- --

# init commands: database + enc-key

init_cmds = AppGroup('init')

def erase_confirm(ctx, param, value):
    if ctx.params['erase_all_data']:
        # The user asked for data to be erased. We now look for a confirmation
        # or prompt the user
        if not value:
            prompt = click.prompt('Do you really want to erase the database?',
                                  type=click.BOOL)
            if not prompt:
                ctx.abort()


@init_cmds.command('database', help="Create tables in the database")
@click.option('--erase-all-data', is_flag=True, help="Erase ALL existing data")
@click.option('--yes', is_flag=True, callback=erase_confirm, expose_value=False,
              help="Erase data without prompting for confirmation")

@with_appcontext
def init_db_command(erase_all_data):
    """
    Create new tables

    The database is initialized and optionally data is cleared.
    """

    if erase_all_data:
        info = 'Recreating database'
    else:
        info = 'Creating database'

    current_app.logger.info(info)

    try:

        setup_db(current_app, erase_all_data)

    except Exception as exx:

        current_app.logger.error(f'Failed to create database: {exx!s}')
        raise click.Abort()

    current_app.logger.info('database created')

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


# -------------------------------------------------------------------------- --

# backend implementation

def setup_db(app, drop_data=False):
    """Set up the database for LinOTP.

    This method is used during create_app() phase and as a separate
    flask command `init-db` in init_db_command() to initialize and setup
    the linotp database.

    FIXME: This is not how we would do this in Flask. We want to
    rewrite it once we get Flask-SQLAlchemy and Flask-Migrate
    working properly.

    :param drop_data: If True, all data will be cleared. Use with caution!
    """

    # Initialise the SQLAlchemy engine

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # sqlite in-memory databases require special sqlalchemy setup:
    # https://docs.sqlalchemy.org/en/13/dialects/sqlite.html#using-a-memory-database-in-multiple-threads

    if sql_uri == "sqlite://":
        engine = create_engine(sql_uri,
                               connect_args={'check_same_thread': False},
                               poolclass=StaticPool)
    else:
        engine = create_engine(sql_uri)

    # Initialise database table model

    init_model(engine)

    # (Re)create and setup database tables if they don't already exist

    app.logger.info("Setting up database...")

    try:
        if drop_data:
            app.logger.info("Dropping tables to erase all data...")
            meta.metadata.drop_all(bind=meta.engine)

        meta.metadata.create_all(bind=meta.engine)

        run_data_model_migration(meta)
        set_defaults(app)

        # For the cloud mode, we require the `admin_user` table to
        # manage the admin users to allow password setting

        admin_username = app.config.get('ADMIN_USERNAME')
        admin_password = app.config.get('ADMIN_PASSWORD')

        if admin_username is not None and admin_password is not None:
            app.logger.info("Setting up cloud admin user...")
            from linotp.lib.tools.set_password import (
                SetPasswordHandler, DataBaseContext
            )
            db_context = DataBaseContext(sql_url=meta.engine.url)
            SetPasswordHandler.create_table(db_context)
            SetPasswordHandler.create_admin_user(
                db_context,
                username=admin_username, crypted_password=admin_password)

    except Exception as exx:
        app.logger.exception(
            "Exception occured during database setup: %r", exx)
        meta.Session.rollback()
        raise exx

    meta.Session.commit()

def create_secret_key(filename):
    """Creates a LinOTP secret file to encrypt and decrypt values in database

    The key file is used via the default security provider to encrypt
    token seeds, configuration values...

    The key file contains 3 key of length 256 bit (32 Byte) each.
    """

    with tempfile.NamedTemporaryFile(mode='wb',
                                     dir=os.path.dirname(filename),
                                     delete=False) as f:
        os.fchmod(f.fileno(), SECRET_FILE_PERMISSIONS)
        f.write(os.urandom(KEY_COUNT * KEY_LENGTH))
    os.replace(f.name, filename)     # atomic rename, since Python 3.3
