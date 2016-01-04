# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

""" Setup the LinOTP application -
                the websetup.py is called for the creating the initial
                data and configuration
"""



from linotp.config.environment import load_environment

try:
    from alembic.config import Config
    alembicconfig_available = True
except ImportError:
    alembicconfig_available = False

try:
    from alembic import command
    alembic_available = True
except ImportError:
    alembic_available = False

import os
import pylons.test


import logging
log = logging.getLogger(__name__)



def setup_app(command, conf, param):
    '''
    setup_app is the hook, which is called, when the application is created

    :param command: - not used -
    :param conf: the application configuration
    :param vars: - not used -

    :return: - nothing -
    '''
    # from http://pylons-webframework.readthedocs.org/en/latest/upgrading.html
    # Add under the 'def setup_app':
    # Don't reload the app if it was loaded under the testing environment
    if not pylons.test.pylonsapp:
        load_environment(conf.global_conf, conf.local_conf)

    unitTest = conf.has_key('unitTest')

    import linotp.lib.base
    linotp.lib.base.setup_app(conf.local_conf, conf.global_conf, unitTest)

    if alembicconfig_available and alembic_available:
        upgrade_databases(conf.local_conf, conf.global_conf)


    return

def upgrade_databases(local_conf, global_conf):
    """
    the database migration is managed by using alembic

     see the alembic.ini file for configuration options
     remark the database urls in the alembic.ini will be
     replaced with the ones of your linotp.ini

     if the writeback of the alembic.ini should not be done,
     this could be specified in the linotp.ini by the option

      alembic.writeback = False

    :param local_conf: the linotp section of the linotp configuration
    :param global_conf: the whole linotp configuration

    :return: -nothing-
    """

    preface = """# This config file is adjusted wrt. the sqlalchemy.urls
# by the websetup.py during
#
#   paster setup-app linotp.ini
#
# Before running alembic manualy, make sure, that the sqlalchemy.url's
# are correct !!
#
# alembic supports you to run the run the database migration by the commands
#
#      alembic upgrade head
# or
#      alembic downgrade -1

"""

    config = local_conf
    here = global_conf.get('here', '')
    alembic_ini = config.get('alembic.ini', "%s/alembic.ini" % here)

    if not os.path.isfile(alembic_ini):
        log.error('No Database migration done as no alembic configuration'
            ' [alembic.ini] could be found!')
        return

    databases = {}
    linotp_url = config.get('sqlalchemy.url', '')
    if linotp_url:
        databases['linotp'] = linotp_url
    audit_url = config.get('linotpAudit.sql.url', '')
    if audit_url:
        table_prefix = config.get("linotpAudit.sql.table_prefix", "")
        databases['audit'] = audit_url
    openid_url = config.get('linotpOpenID.sql.url', '')
    if openid_url:
        databases['openid'] = openid_url

    # load the alembic configuration
    alembic_cfg = Config(alembic_ini)

    for database in databases:
        if database == 'audit':
            alembic_cfg.set_section_option(database, 'table_prefix', table_prefix)
        alembic_cfg.set_section_option(database, 'sqlalchemy.url', databases.get(database))

    alembic_cfg.set_section_option('alembic', 'databases', ','.join(databases.keys()))

    if config.get('alembic.writeback', 'false').lower() == 'true':
        fileConfig = alembic_cfg.file_config
        with open(alembic_ini, 'w') as cfgfile:
            cfgfile.write(preface)
            fileConfig.write(cfgfile)

    try:
        if config.get('alembic.auto_update', 'false').lower() == 'true':
            command.upgrade(alembic_cfg, "head")
    except Exception as exx:
        log.exception('error during upgrade %r' % exx)

    return
###eof#########################################################################

