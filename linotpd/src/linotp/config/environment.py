# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""  Pylons environment configuration """

import os

from mako.lookup import TemplateLookup
from pylons import config
from pylons.error import handle_mako_error
from sqlalchemy import engine_from_config

import linotp.lib.app_globals as app_globals
import linotp.lib.helpers

from linotp.useridresolver import resolver_registry
from linotp.useridresolver import UserIdResolver
from linotp.config.routing import make_map
from linotp.lib.error import TokenTypeNotSupportedError


import sys
import inspect
import pkg_resources

import warnings
warnings.filterwarnings(action='ignore', category=DeprecationWarning)


def _uniqify_list(input_list):
    """
    Returns a list containing only unique elements from input_list whilst
    preserving the original order.
    See http://www.peterbe.com/plog/uniqifiers-benchmark
    """
    seen = {}
    result = []
    for item in input_list:
        if item in seen:
            continue
        seen[item] = 1
        result.append(item)
    return result


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
    """

    # Pylons paths
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = dict(root=root,
                 controllers=os.path.join(root, 'controllers'),
                 static_files=os.path.join(root, 'public'),
                 templates=[app_conf.get('custom_templates',
                                         os.path.join(root, 'templates')),
                            os.path.join(root, 'templates')])

    # Initialize config with the basic options
    config.init_app(global_conf, app_conf, package='linotp', paths=paths)

    config['linotp.root'] = root
    config['routes.map'] = make_map(global_conf, app_conf)
    config['pylons.app_globals'] = app_globals.Globals()
    config['pylons.h'] = linotp.lib.helpers

    # add per token a location for the mako template lookup
    # @note: the location is defined in the .ini file by
    # the entry [linotpTokenModules]

    directories = paths['templates']

    import linotp.tokens as token_package

    token_package_path = os.path.dirname(token_package.__file__)
    directories.append(token_package_path)

    for token_package_sub_path, _subdir, _files in os.walk(token_package_path):
        directories.append(token_package_sub_path)

    # add a template path for every resolver
    resolver_module_path = UserIdResolver.__file__
    directories.append(resolver_module_path)

    unique_directories = _uniqify_list(directories)
    log.debug("[load_environment] Template directories: %r" % unique_directories)

    config['pylons.app_globals'].mako_lookup = TemplateLookup(
        directories=unique_directories,
        error_handler=handle_mako_error,
        module_directory=os.path.join(app_conf['cache_dir'], 'templates'),
        input_encoding='utf-8', default_filters=['escape'],
        imports=['from webhelpers.html import escape'])

    # Setup the SQLAlchemy database engine
    # If we load the linotp.model here, the pylons.config is loaded with
    # the entries from the config file. if it is loaded at the top of the file,
    # the pylons.config does not contain the config file, yet.
    from linotp.model import init_model
    engine = engine_from_config(config, 'sqlalchemy.')
    init_model(engine)

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    # any Pylons config options)

    from linotp.lib.audit.base import getAudit
    audit = getAudit(config)
    config['audit'] = audit

    # setup Security provider definition
    try:
        log.debug('[load_environment] loading token list definition')
        g = config['pylons.app_globals']
        g.security_provider.load_config(config)
    except Exception as e:
        log.exception("Failed to load security provider definition: %r" % e)
        raise e

    # get the help url
    url = config.get("linotpHelp.url", None)
    if url is None:
        version = pkg_resources.get_distribution("linotp").version
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
