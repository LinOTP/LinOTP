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
import binascii
import shutil
import subprocess

from datetime import datetime

from flask import current_app
from sqlalchemy.ext.serializer import loads, dumps

from sqlalchemy import create_engine

from linotp.model.meta import Session as session
from linotp.model import Config, Token, TokenRealm, Realm
from linotp.model import Reporting, LoggingConfig
from linotp.model import init_model, meta

from linotp.lib.audit.SQLAudit import AuditTable

EXIT_OK = 0
EXIT_ERROR = 1

ORM_Models = {
    'Config': Config, 
    'Token': Token, 
    'TokenRealm': TokenRealm, 
    'Realm': Realm
    }

def which(program:str) -> str:
    """
    helper to identify a program in the environment path

    @param program: the name of the program
    @return executable with absolute path
    """

    path = os.environ.get('PATH')
    exececutable = shutil.which(program, path=path)

    if not exececutable:
        path = path + os.pathsep + "/usr/local/bin"
        exececutable = shutil.which(program, path=path)

    return exececutable

def backup_audit_tables(app):
    """
    create a dedicated backup of the audit database

    @param app : the current app
    """

    backup_filename_template = "linotp_audit_backup_%s.sqldb"

    audit_uri = app.config["AUDIT_DATABASE_URI"]
    if audit_uri == 'SHARED':
        audit_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    backup_classes = {}
    backup_classes['AuditTable'] = AuditTable

    return backup_tables(
        app, audit_uri, backup_filename_template, backup_classes)


def backup_database_tables(app):
    """
    use the sqlalchemy serializer to dump the database mapped objects

    @param app : the current app
    """

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

    # run the backup

    return backup_tables(app, sql_uri, backup_filename_template, backup_classes)


def backup_tables(app, sql_uri, backup_file_template, backup_classes):
    """
    use the sqlalchemy serializer to dump the database mapped objects
    - lower level backend used by backup database and backup audit
 
    @param app : the current app
    @param sql_uri - the database uri to connect
    @param backup_filename_template - store the audit or as std backup file
    @param backup_classes - list of orm classes that should be queried
    """

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    engine = create_engine(sql_uri)

    init_model(engine)

    app.logger.info("extracting data from: %r:%r" % 
                    (engine.url.drivername, engine.url.database))

    # ---------------------------------------------------------------------- --

    # setup the backup location

    backup_dir = current_app.config["BACKUP_DIR"]
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    # ---------------------------------------------------------------------- --

    # determin the datetime extension

    now = datetime.now()
    now_str = now.strftime('%y%m%d%H%M')

    # ---------------------------------------------------------------------- --

    # run the db serialisation and dump / pickle the data

    backup_filename = os.path.join(
        backup_dir, backup_filename_template % now_str)

    app.logger.info("creating backup file: %s" % backup_filename)

    with open(backup_filename, "w") as backup_file:

        for name, model_class in backup_classes.items():

            app.logger.info("saving %s" % name)

            backup_file.write("--- BEGIN %s\n" % name)

            data_query = session.query(model_class)
            for data in data_query.all():
                serialized = dumps(data)
                backup_file.write(binascii.hexlify(serialized).decode('utf-8'))

            backup_file.write("\n--- END %s\n" % name)

    return EXIT_OK

def list_database_backups(app):
    """
    find all backup files in the backup directory

    @param app : the current app
    @return list of backup dates
    """

    return list_backups(app, filename_template='linotp_backup_')

def list_audit_backups(app):
    """
    find all audit backup files in the backup directory

    @param app : the current app
    @return list of backup dates
    """

    return list_backups(app, filename_template='linotp_audit_backup_')

def list_backups(app, file_template):
    """
    find all backup files in the backup directory

    @param app : the current app
    @param file_template - either the audit or the std backup file name
    @return list of backup dates
    """

    # ---------------------------------------------------------------------- --

    # setup the backup location

    backup_dir = current_app.config["BACKUP_DIR"]

    if not os.path.isdir(backup_dir):
        app.logger.error("no backup directory found: %s" % backup_dir)
        os.mkdir(backup_dir)
        app.logger.error("backup directory created: %s" % backup_dir)
    # ---------------------------------------------------------------------- --

    # lookup for all files in the directory that match the template

    backups = []

    for backup_file in os.listdir(backup_dir):

        # backup files match the 'template' + "%s.sqldb" format

        if (backup_file.startswith(filename_template)
            and backup_file.endswith('.sqldb')):

            backup_date, _, _ext = backup_file[
                len(filename_template):].rpartition('.')

            backups.append(backup_date)

    app.logger.info("backups for dates found: %r" % sorted(backups))

    return sorted(backups)

# -------------------------------------------------------------------------- --

# restore

def _get_restore_filename(app, template, file=None, date=None):
    """
    helper for restore, to determin a filename from a given date or file name

    @param app - the current app
    @param template - the file name template to search for
    @param filename - the absolute or relative backup file name
    @param date - find a backup file by date
    @return the matching filename or None
    """

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
        app.logger.error(
            "failed to restore - not date or file name parameter provided")
        return None

    # ---------------------------------------------------------------------- --

    # verify that the file to restore from exists

    if not os.path.isfile(backup_filename):

        app.logger.info(
            "failed to restore %s - not found or not accessible"
            % backup_filename)
        return None

    return backup_filename


def restore_audit_table(app, file:str =None, date:str =None):
    """
    restore audit only backup file

    @param app - the current app
    @param filename - the absolute or relative backup file name
    @param date - find a backup file by date
    """
    restore_names = ['AuditTable']

    # ---------------------------------------------------------------------- --

    # determin the backup file for the audit restore

    backup_filename = _get_restore_filename(
                        app, "linotp_audit_backup_%s.sqldb", filename, date)

    if not backup_filename:
        return EXIT_ERROR

    # ---------------------------------------------------------------------- --

    # get the database uri for audit or fallback to sql uri if the audit is
    # shared in the same database

    sql_uri = app.config["AUDIT_DATABASE_URI"]
    if sql_uri == 'SHARED':
        sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # ---------------------------------------------------------------------- --

    # run the restore of the audit table

    return restore_tables(app, sql_uri, backup_filename, restore_names)

def restore_database_tables(
        app, file:str =None, date:str =None, table:str =None):
    """
    restore the database tables from a file or for a given date
       optionally restore only one table

    @param app - the current app
    @param filename - the absolute or relative backup file name
    @param date - find a backup file by date
    @param table - restore only one database table e.g. tokens
    """

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
            app.logger.error(
                f"selected table {table} is not in the set of supported tables"
                )
            return EXIT_ERROR

    # ---------------------------------------------------------------------- --

    # determine the backup file for the database restore

    backup_filename = _get_restore_filename(
                        app, "linotp_backup_%s.sqldb", filename, date)

    if not backup_filename:
        return EXIT_ERROR

    # ---------------------------------------------------------------------- --

    # get the database uri for the linotp database

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # ---------------------------------------------------------------------- --

    # run the restore of the list of tables into the database

    return restore_tables(app, sql_uri, backup_filename, restore_names)

def restore_tables(app, sql_uri:str, backup_file:str, restore_names: list):
    """
    use the sqlalchemy de-serializer to restore the database mapped objects

    @param app - the current app
    @param sql_uri - the target sql database uri
    @param backup_filename - the file with the serialized db objects
    @param restore_names - list of table names to restore
    """
    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    engine = create_engine(sql_uri)

    init_model(engine)

    # ---------------------------------------------------------------------- --

    # restore the sqlalchemy dump from file

    with open(backup_filename, "r") as backup_file:

        line = backup_file.readline()

        while line:

            if line:
                line = line.strip()

            if not line:
                line = backup_file.readline()
                continue

            if line.startswith('--- END '):
                name = None
                line = backup_file.readline()
                continue

            if line.startswith('--- BEGIN '):
                name = line[len('--- BEGIN '):]
                line = backup_file.readline()
                continue

            if name in restore_names:

                # unhexlify the serialized data first

                data = binascii.unhexlify(line.encode('utf-8'))

                # use sqlalchemy loads to de-serialize the data objects

                restore_query = loads(data, meta.metadata, session)

                # merge the objects into the current session

                session.merge(restore_query)

                app.logger.info("restoring %r" % name)

            line = backup_file.readline()

    # finally commit all de-serialized objects

    session.commit()

    return EXIT_OK

def restore_legacy_database(app:LinOTPApp, file:str) -> int:
    """
    restore the mysql dump of a former linotp tools backup

    @param file: backup file name - absolute filename
    """

    backup_filename = os.path.abspath(filename.strip())

    if not os.path.isfile(backup_filename):
        app.logger.error("legacy backup file %r could not be accessed."
                         % filename)
        return EXIT_ERROR

    # ---------------------------------------------------------------------- --

    # setup db engine, session and meta from sql uri

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    engine = create_engine(sql_uri)

    if 'mysql' not in engine.url.drivername:
        app.logger.error("legacy backup file could only restored in a"
                         " mysql database. current database driver is %r" %
                          engine.url.drivername)
        return EXIT_ERROR

    # ---------------------------------------------------------------------- --

    # determine the mysql command parameters

    mysql = which('mysql')
    if not mysql:
        app.logger.error("mysql executable not found in path")
        return EXIT_ERROR

    username = engine.url.username
    database = engine.url.database
    host = engine.url.host
    password = engine.url.password_original
    port = engine.url.port or '3306'

    command = [
        f'{mysql}',
        f'--user={username}',
        f'--password={password}',
        f'--host={host}',
        f'--port={port}',
        '-D', f'{database}'
        ]

    # ---------------------------------------------------------------------- --

    # run the restore in subprocess

    app.logger.info("restoring backup %r" % backup_filename)

    with open(backup_filename, 'r') as backup_file:
        result = subprocess.run(
            command, stdin=backup_file, capture_output=True)

        if result.returncode != EXIT_OK:
            app.logger.info("failed to restore legacy backup file: %s"
                            % result.stderr.decode('utf-8'))
        else:
            app.logger.info("legacy backup file restored: %s"
                            % result.stdout.decode('utf-8'))

        return result.returncode

    return EXIT_ERROR
