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
"""Contains SetConfig class to call system/setConfig"""

import logging

from .test_case import TestCase

LOG = logging.getLogger(__name__)


class SetConfig:
    def __init__(self, testcase: TestCase):
        """Initializes the class with the required values to call
        https://.../system/setConfig
        """
        self.testcase = testcase

    def setConfig(self, parameters):
        """Sets the config with the parameters"""
        return self.testcase.manage_ui.admin_api_call(
            "/system/setConfig",
            parameters,
        )
