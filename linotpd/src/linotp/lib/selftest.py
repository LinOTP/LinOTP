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
check if we are running in selftest mode
"""

import logging

from linotp.lib.config import getFromConfig

log = logging.getLogger(__name__)


def isSelfTest(config=None):
    '''
    check if we are running in the selftest mode, which is
    used especially for debugging / development or unit tests

    :param config: config dictionary
    :return: boolean
    '''

    if not config:
        selftest = getFromConfig("selfTest", False) is not False
    else:
        selftest = config.get("selfTest", False) is not False

    return selftest

# eof ########################################################################
