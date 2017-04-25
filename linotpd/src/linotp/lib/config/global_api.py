# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

from linotp.config import environment as env

global_object = env.config.get('pylons.app_globals', env.config.get(
                                'pylons.g'))


def getGlobalObject():
    return global_object


def _getConfigReadLock():
    getGlobalObject().setConfigReadLock()


def _getConfigWriteLock():
    getGlobalObject().setConfigWriteLock()


def _releaseConfigLock():
    getGlobalObject().releaseConfigLock()

# eof #
