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
"""
Tests a very small subset of linotp.lib.reply
"""

import json
import unittest
from mock import (
    MagicMock,
    PropertyMock,
    )
from linotp.lib.reply import sendResultIterator
from linotp.lib.error import ProgrammingError
from linotp.lib.context import request_context


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

    def test_response_iterator_request_context(self):

        """ test if request context gets reinstated in sendResultIterator """

        def request_context_test_iterator():
            # this will raise an error if it is called
            # outside of request_context_safety
            yield request_context.get('foo')

        # we need to enclose bar into double qoutes,
        # because the json is assembled manually
        request_context_copy = {'foo': '"bar"'}

        try:
            res = sendResultIterator(request_context_test_iterator(),
                                     request_context_copy=request_context_copy)
        except ProgrammingError:
            self.assertTrue(False, 'request_context was used outside'
                                   'of request_context_safety')

        result = ""
        for chunk in res:
            result += chunk

        result_dict = json.loads(result)
        value = result_dict.get('result', {}).get('value')

        self.assertIn(u'bar', value)
