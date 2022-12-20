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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
Tests the chunked data handling in the config
"""


import unittest

from mock import patch

from linotp.model.meta import Session
from linotp.lib.user import User
from linotp.controllers.userservice import UserserviceController


class MockUserserviceController(UserserviceController):
    """
    for the unit test we need only the (static) method,
    so we omit the class constructor of a controller
    """

    def __init__(self):
        return

# -------------------------------------------------------------------------- --

# we use a mock class for the global c


class Mock_C(object):
    audit = {}

# -------------------------------------------------------------------------- --


class TestUserservice(unittest.TestCase):

    def tearDown(self):
        Session.remove()

    @patch('linotp.controllers.userservice.c', Mock_C())
    @patch('linotp.controllers.userservice.sendResult')
    def test_otp_auth(self, mock_sendResult):
        """
        verify that the unbound local error is not raised anymore
        """

        class MockUser(User):
            def checkPass(self, password):
                return False

        mock_sendResult.return_value = 'ok'

        user = MockUser('hans', 'realm')
        passw = 'test123'
        param = {'otp': '123456'}

        unboundLocalError_raised = False

        try:
            userservice = MockUserserviceController()
            result = userservice._login_with_otp(user, passw, param)

        except UnboundLocalError as exx:
            unboundLocalError_raised = exx

        self.assertFalse(unboundLocalError_raised, unboundLocalError_raised)
        self.assertTrue(result == 'ok')

        return

# eof
