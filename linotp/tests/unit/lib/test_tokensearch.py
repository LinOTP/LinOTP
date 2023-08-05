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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
Tests the token search
- with single char wildcard
"""

import unittest

from mock import patch

from linotp.lib.tokeniterator import TokenIterator  # _get_user_condition
from linotp.lib.user import User


class TestTokenSearch(unittest.TestCase):
    @patch("linotp.lib.tokeniterator.getTokens4UserOrSerial")
    @patch("linotp.lib.tokeniterator.token_owner_iterator")
    @patch("linotp.lib.tokeniterator.TokenIterator.__init__")
    def test_singechar_wildcard(
        self,
        mocked_tokenIterator_init,
        mocked_token_owner_iterator,
        mocked_getTokens4UserOrSerial,
    ):
        valid_realms = ["*"]

        mocked_tokenIterator_init.return_value = None
        tik = TokenIterator(None, None)

        # ------------------------------------------------------------------ --

        # test the old behaviour with '*' wildcard, which takes the
        # expensive code path

        user = User(login="pass*thru", realm="user2")
        tik._get_user_condition(user, valid_realms)

        assert mocked_token_owner_iterator.call_count == 1

        # ------------------------------------------------------------------ --

        mocked_token_owner_iterator.called = False
        mocked_token_owner_iterator.call_count = 0

        # ------------------------------------------------------------------ --

        # now test the setting of the '.' which causes a differen code path

        mocked_getTokens4UserOrSerial.return_value = []

        user = User(login="pass.thru", realm="user2")
        tik._get_user_condition(user, valid_realms)

        assert not mocked_token_owner_iterator.called
        assert mocked_getTokens4UserOrSerial.call_count == 1

        return


# eof #
