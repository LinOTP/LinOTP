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
#
"""  Pylons environment configuration """

import os

import flask

from mako.lookup import TemplateLookup
from linotp.flap import config, handle_mako_error
# from sqlalchemy import create_engine

from linotp.useridresolver import resolver_registry
from linotp.useridresolver import UserIdResolver
from linotp.config.routing import make_map
from linotp.lib.error import TokenTypeNotSupportedError


import sys
import inspect
import pkg_resources

import warnings
warnings.filterwarnings(action='ignore', category=DeprecationWarning)


def fxn():
    warnings.warn("deprecated", DeprecationWarning)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    fxn()

import logging

log = logging.getLogger(__name__)


def load_environment(global_conf, app_conf):
    """
    Configure the Pylons environment via the ``pylons.config``
    object

    @param app_conf Flask configuration
    """
    from linotp.lib.config.global_api import initGlobalObject
    initGlobalObject()

    import linotp.tokens as token_package

    token_package.reload_classes()

    # Setup the SQLAlchemy database engine
    # If we load the linotp.model here, the pylons.config is loaded with
    # the entries from the config file. if it is loaded at the top of the file,
    # the pylons.config does not contain the config file, yet.
    # NB: With Flask, this shouldn't matter because we have the
    # `SQLALCHEMY_DATABASE_URI` in the Flask-side configuration.
    # from linotp.model import init_model
    # engine = create_engine(config['SQLALCHEMY_DATABASE_URI'])
    # init_model(engine)

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    # any Pylons config options)

    from linotp.lib.audit.base import getAudit
    audit = getAudit(config)
    config['audit'] = audit

    # setup Security provider definition
    try:
        log.debug('[load_environment] loading security provider pool')
        from linotp.lib.config.global_api import getGlobalObject
        getGlobalObject().security_provider.load_config(config)
    except Exception as e:
        log.exception("Failed to load security provider definition: %r" % e)
        raise e

    # get the help url
    url = config.get("linotpHelp.url", None)
    if url is None:
        # version = pkg_resources.get_distribution("linotp").version
        # TODO
        version = 3
        # First try to get the help for this specific version
        url = "https://linotp.org/doc/%s/index.html" % version
    config['help_url'] = url

    log.debug("[load_environment] done")

    return config

#######################################


def get_activated_token_modules():

    """
    checks in the ini file for the linotpTokenModules key and returns
    the list of modules defined there as a list. if the key is not
    present this will return None.
    """
    config = flask.g.request_context['config']
    if 'linotpTokenModules' not in config:
        return None

    module_list = []
    module_config_str = config.get('linotpTokenModules')

    # in the config *.ini files we have some line continuation slashes,
    # which will result in ugly module names, but as they are followed by
    # \n they could be separated as single entries by the following two
    # lines
    lines = module_config_str.splitlines()
    coco = ",".join(lines)
    for module in coco.split(','):

        if module.strip() == '\\':
            continue

        if module.strip() == '':
            continue

        module_list.append(module.strip())

    return module_list


###eof#########################################################################
