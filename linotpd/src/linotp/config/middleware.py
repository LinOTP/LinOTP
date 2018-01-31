# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
"""Pylons middleware initialization"""

from beaker.middleware import CacheMiddleware, SessionMiddleware
from paste.cascade import Cascade
from paste.registry import RegistryManager
from paste.urlparser import StaticURLParser
from paste.deploy.converters import asbool
from pylons import config
from pylons.middleware import ErrorHandler, StatusCodeRedirect
from pylons.wsgiapp import PylonsApp
from routes.middleware import RoutesMiddleware
from linotp.config.environment import load_environment
from contextlib import contextmanager

#
# pylint has problems to identity the location distutils.version
# which is different to the distutils location.
# Thus we beg to ignore the high prio warning by adding the pylint hint
#
# pragma pylint: disable=import-error
# pragma pylint: disable=no-name-in-module
from distutils.version import LooseVersion
# pragma pylint: enable=import-error
# pragma pylint: enable=no-name-in-module

from pylons import __version__ as pylons_version

# for pylons versions lower or equesl to 0.9.8
# we have to use a dummy class based on dict
if LooseVersion(pylons_version) > LooseVersion('0.9.7'):
    from pylons.configuration import PylonsConfig as PyConf
else:
    class PyConf(dict):
        pass


import binascii
import re
import os
import tempfile

def make_app(global_conf, full_stack=True, static_files=True, **app_conf):
    """
    Create a Pylons WSGI application and return it

    ``global_conf``
        The inherited configuration for this application. Normally from
        the [DEFAULT] section of the Paste ini file.

    ``full_stack``
        Whether this application provides a full WSGI stack (by default,
        meaning it handles its own exceptions and errors). Disable
        full_stack when this application is "managed" by another WSGI
        middleware.

    ``static_files``
        Whether this application serves its own static files; disable
        when another web server is responsible for serving them.

    ``app_conf``
        The application's local configuration. Normally specified in
        the [app:<name>] section of the Paste ini file (where <name>
        defaults to main).

    """
    # Configure the Pylons environment
    config = load_environment(global_conf, app_conf)

    # The Pylons WSGI app
    app = PylonsApp()

    # Routing/Session/Cache Middleware
    app = RoutesMiddleware(app, config['routes.map'])
    app = SessionMiddleware(app, config)
    app = CacheMiddleware(app, config)

    g = config['pylons.app_globals']
    g.cache_manager = app.cache_manager

    # CUSTOM MIDDLEWARE HERE (filtered by error handling middlewares)

    if asbool(full_stack):
        # Handle Python exceptions
        app = ErrorHandler(app, global_conf, **config['pylons.errorware'])

        # Display error documents for 401, 403, 404 status codes (and
        # 500 when debug is disabled)
        if asbool(config['debug']):
            app = StatusCodeRedirect(app)
        else:
            app = StatusCodeRedirect(app, [400, 401, 403, 404, 500])

    # Establish the Registry for this application
    app = RegistryManager(app)

    if asbool(static_files):
        # Serve static files
        static_app = StaticURLParser(config['pylons.paths']['static_files'])
        app = Cascade([static_app, app])

    # this is a compatibility hack for pylons > 1.0!!!
    conf = PyConf(config)

    conf['global_conf'] = global_conf
    conf['app_conf'] = app_conf
    conf['__file__'] = global_conf['__file__']
    conf['FILE'] = global_conf['__file__']
    conf['routes.map'] = config['routes.map']

    if not hasattr(conf, 'init_app'):
        setattr(conf, 'init_app', config.init_app)
    app.config = conf

    return app


@contextmanager
def tempinput(data):
    """
    Create a temporary file containing data.
    Uses contextmanager to make sure that the file is deleted after use.
    :param data: Contents of temporary file
    :return: Filename of temporary file
    """
    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.write(data)
    temp.close()
    yield temp.name
    os.unlink(temp.name)
