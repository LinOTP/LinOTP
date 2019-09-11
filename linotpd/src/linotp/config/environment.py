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

    # setup Security provider definition
    try:
        log.debug('[load_environment] loading security provider pool')
        from linotp.lib.config.global_api import getGlobalObject
        getGlobalObject().security_provider.load_config(config)
    except Exception as e:
        log.exception("Failed to load security provider definition: %r" % e)
        raise e

    log.debug("[load_environment] done")

    return config

#######################################


def get_activated_token_modules():

    """
    checks the setting for token modules to be activated and returns
    the list of modules defined there as a list. If the key is not
    present or has an empty value this will return an empty list.
    """

    token_modules = flask.current_app.config.get("TOKEN_MODULES", "")
    if not token_modules:
        return []
    return token_modules.split()

###eof#########################################################################
