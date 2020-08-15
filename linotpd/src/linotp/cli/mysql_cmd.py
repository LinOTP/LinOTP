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
mysql database backup implementation
"""

import os
import sys
from datetime import datetime
import subprocess
import click

TIME_FORMAT = '%y%m%d%H%M'

from flask import current_app
from flask.cli import AppGroup

from sqlalchemy import create_engine

from linotp.app import LinOTPApp


# -------------------------------------------------------------------------- --

# backup legacy commands: restore (+ backup == to be implemented and tested)

backup_cmds = AppGroup('backup-legacy')

@backup_cmds.command('restore',
                      help='restore a mysql backup file')
@click.option('--file', help='name of the mysql backup file')
def restore_mysql_command(file):
    """ restore mysql backups."""
    try:
        current_app.logger.info("Restoring legacy database ...")
        restore_mysql_database(filename=file)
        current_app.logger.info("finished")
    except Exception as exx:
        current_app.logger.error('Failed to restore mysql backup: %r' % exx)
        sys.exit(1)


@backup_cmds.command('create',
                      help='create a backup file via mysqldump')
def backup_mysql_command():
    """ backup mysql database."""
    try:
        current_app.logger.info("Backup mysql database ...")
        backup_mysql_database()
        current_app.logger.info("finished")
    except Exception as exx:
        current_app.logger.error('Failed to backup mysql: %r' % exx)
        sys.exit(1)

# -------------------------------------------------------------------------- --

# backend implementation

def backup_mysql_database():
    """ backup the mysql database via mysqldump

    similar to the original bash script, thus
    - using the same time-stamp format
    - backup of the enckey
    """
    app = current_app

    now = datetime.now()
    now_str = now.strftime(TIME_FORMAT)

    filename = f'linotp_backup_{now_str}.sql'
    backup_filename = os.path.abspath(filename)
    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    engine = create_engine(sql_uri)

    if 'mysql' not in engine.url.drivername:
        app.logger.error("mysql backup file could only restored in a"
                         " mysql database. current database driver is %r" %
                          engine.url.drivername)
        raise click.Abort()

    # ---------------------------------------------------------------------- --

    # determine the mysql command parameters

    username = engine.url.username
    database = engine.url.database
    host = engine.url.host
    password = engine.url.password_original
    port = engine.url.port or '3306'

    command = [
        'mysqldump',
        f'--user={username}',
        f'--password={password}',
        f'--port={port}',
        f'--host={host}',
        f'--result-file={backup_filename}',
        f'{database}']

    # ---------------------------------------------------------------------- --

    # run the backup in subprocess

    app.logger.info("mysql backup %r" % backup_filename)

    cmd = " ".join(command)
    result = subprocess.call(cmd, shell=True)

    if result != 0 or not os.path.isfile(backup_filename):
        app.logger.error("failed to create mysql backup file: %r" % result)
        raise click.Abort()

    app.logger.info("mysql backup file %s created!" % backup_filename)

def restore_mysql_database(filename:str):
    """
    restore the mysql dump of a former linotp tools backup

    @param file: backup file name - absolute filename
    """
    app = current_app

    backup_filename = os.path.abspath(filename.strip())

    if not os.path.isfile(backup_filename):
        app.logger.error("mysql backup file %r can not be accessed."
                         % filename)
        raise click.Abort()

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    engine = create_engine(sql_uri)

    if 'mysql' not in engine.url.drivername:
        app.logger.error("mysql backup file can only be restored in a"
                         " mysql database. current database driver is %r" %
                          engine.url.drivername)
        raise click.Abort()

    # ---------------------------------------------------------------------- --

    # determine the mysql command parameters

    username = engine.url.username
    database = engine.url.database
    host = engine.url.host
    password = engine.url.password_original
    port = engine.url.port or '3306'

    command = [
        'mysql',
        f'--user={username}',
        f'--password={password}',
        f'--host={host}',
        f'--port={port}',
        '-D', f'{database}'
        ]

    # ---------------------------------------------------------------------- --

    # run the restore in subprocess

    app.logger.info("restoring mysql backup %r" % backup_filename)

    msg = ''

    with open(backup_filename, 'r') as backup_file:
        result = subprocess.run(
            command, stdin=backup_file, capture_output=True)

        if result.returncode != 0:
            app.logger.info("failed to restore mysql backup file: %s"
                            % result.stderr.decode('utf-8'))
            raise click.Abort()

        msg = result.stdout.decode('utf-8')

    app.logger.info("mysql backup file restored: %s" % msg)


