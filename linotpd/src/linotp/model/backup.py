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

from datetime import datetime

from flask import current_app
from sqlalchemy.ext.serializer import loads, dumps

from sqlalchemy import create_engine

from linotp.model.meta import Session as session
from linotp.model import Config, Token, TokenRealm, Realm
from linotp.model import Reporting, LoggingConfig
from linotp.model import init_model, meta

from linotp.lib.audit.SQLAudit import AuditTable


ORM_Models = {
    'Config': Config, 
    'Token': Token, 
    'TokenRealm': TokenRealm, 
    'Realm': Realm
    }

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

    backup_tables(app, audit_uri, backup_file_template, backup_classes)


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

    backup_tables(app, sql_uri, backup_file_template, backup_classes)


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

def list_database_backups(app):
    """
    find all backup files in the backup directory

    @param app : the current app
    @return list of backup dates
    """

    return list_backups(app, file_template='linotp_backup_')

def list_audit_backups(app):
    """
    find all audit backup files in the backup directory

    @param app : the current app
    @return list of backup dates
    """

    return list_backups(app, file_template='linotp_audit_backup_')

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
