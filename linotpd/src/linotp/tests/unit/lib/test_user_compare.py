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

import unittest
from mock import patch

from linotp.lib.user import User
from linotp.lib.token import TokenHandler

class MockedToken():

    def getUser(self):
        return ('1234', 'resolver info', 'passwdResolver.conf1')


class TestUserCompare(unittest.TestCase):

    @patch('linotp.lib.token.getTokens4UserOrSerial')
    @patch('linotp.lib.token.getUserId')
    def test_compare_user(self,
                          mocked_getUserId,
                          mocked_getTokens4UserOrSerial):
        """
        test for isTokenOwner
        
        the isTokenOwner should only compare the resolver conf and user id
        """

        th = TokenHandler()

        user = User(login='hugo', realm='realm',
                    resolver_config_identifier='blah')

        # ----------------------------------------------------------------- --

        # test for same user as uid is the same and the resolver class with
        # conf is the same, only the resolver description is different

        mocked_getUserId.return_value = ('1234', 'migrated resolver info',
                                         'passwdResolver.conf1')
        mocked_getTokens4UserOrSerial.return_value = [MockedToken()]

        result = th.isTokenOwner('TokenSerial', user)

        self.assertTrue(result)

        # ----------------------------------------------------------------- --

        # test for different user as uid is the same and the resolver class
        # with different conf, but same resolver description

        mocked_getUserId.return_value = ('1234', 'resolver info',
                                         'passwdResolver.conf2')
        mocked_getTokens4UserOrSerial.return_value = [MockedToken()]

        result = th.isTokenOwner('TokenSerial', user)

        self.assertFalse(result)

        return


# eof #
