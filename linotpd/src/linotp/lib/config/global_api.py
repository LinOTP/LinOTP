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
"""
    helper to manage the pylons global object
"""

from flask import g as flask_g

from linotp.lib.app_globals import Globals

def getGlobalObject():

    return flask_g.app_globals

def initGlobalObject():
    """
    Initialise global object and save to the global context
    """
    flask_g.app_globals = Globals()


def _getConfigReadLock():
    # getGlobalObject().setConfigReadLock()
    pass


def _getConfigWriteLock():
    # getGlobalObject().setConfigWriteLock()
    pass


def _releaseConfigLock():
    # getGlobalObject().releaseConfigLock()
    pass

# eof #
