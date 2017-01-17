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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
Tests a very small subset of linotp.lib.reply
"""

import unittest
from mock import (
    MagicMock,
    PropertyMock,
    )


class TestReplyTestCase(unittest.TestCase):
    def setUp(self):
        self.pylons_request = MagicMock(spec=['params', 'query_string'])

    def test_httperror_set_and_valid(self):
        from linotp.lib.reply import _get_httperror_from_params
        self.pylons_request.params = {
            'httperror': '777',
            }
        self.pylons_request.query_string = 'httperror=777'
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, '777')
        #self.assertFalse(self.pylons_request.query_string.called)

    def test_httperror_set_and_invalid(self):
        from linotp.lib.reply import _get_httperror_from_params
        self.pylons_request.params = {
            'httperror': 'somestr',
            }
        self.pylons_request.query_string = 'httperror=somestr'
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, '500')

    def test_httperror_set_and_empty(self):
        from linotp.lib.reply import _get_httperror_from_params
        self.pylons_request.params = {
            'httperror': '',
            }
        self.pylons_request.query_string = 'httperror'
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, '500')

    def test_httperror_unset(self):
        from linotp.lib.reply import _get_httperror_from_params
        self.pylons_request.params = {}
        self.pylons_request.query_string = ''
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, None)

    def test_httperror_with_UnicodeDecodeError(self):
        from linotp.lib.reply import _get_httperror_from_params
        # Raising exceptions on attribute access
        prop_mock = PropertyMock(
            side_effect=UnicodeDecodeError(
                'utf8',
                '\xc0',
                0,
                1,
                'invalid start byte'
                )
            )
        type(self.pylons_request).params = prop_mock
        self.pylons_request.query_string = 'httperror=555'
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, '555')

    def test_httperror_with_UnicodeDecodeError_and_mult_param(self):
        from linotp.lib.reply import _get_httperror_from_params
        # Raising exceptions on attribute access
        prop_mock = PropertyMock(
            side_effect=UnicodeDecodeError(
                'utf8',
                '\xc0',
                0,
                1,
                'invalid start byte'
                )
            )
        type(self.pylons_request).params = prop_mock
        self.pylons_request.query_string = 'httperror=555&httperror=777'
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, '777')

    def test_httperror_with_Exception(self):
        from linotp.lib.reply import _get_httperror_from_params
        # Raising exceptions on attribute access
        prop_mock = PropertyMock(side_effect=Exception("Random exception"))
        type(self.pylons_request).params = prop_mock
        self.pylons_request.query_string = 'httperror=555'
        httperror = _get_httperror_from_params(self.pylons_request)
        self.assertEquals(httperror, None)
