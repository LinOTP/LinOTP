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

""" test for json body as request parameters """

import copy
import unittest

from mock import mock

from linotp.lib.base import BaseController
from webob.multidict import NestedMultiDict
from webob.multidict import MultiDict


def create_multidict(*args):
    """
    Create a pylons NestedMultiDict object from tuple lists
        args = [[('k', '1'), ('k', '2'), ('k', '3')], [('l', 'Z')]]
    :params args: list of list of tuples
    :returns: NestedMultiDict object
    """
    multi_dicts = []
    for arg in args:
        multi_dicts.append(MultiDict(arg))

    return NestedMultiDict(*multi_dicts)


class TestBaseController(unittest.TestCase):
    """
    test for request parameter handling to support parameters from json body
    """

    @mock.patch('linotp.lib.base.request')
    @mock.patch('linotp.lib.base.BaseController.__init__', return_value=None)
    def test_multidict_params(self, _mock_base, mock_request):
        """"
        check if global request.params gets parsed to a plain dict correctly
        """

        expected_params = {'k': ['1', '2'], 'l': 'Z'}

        arg1 = [('k[]', '1'), ('k[]', '2')]
        arg2 = [('l', 'Z')]

        mock_request.params = create_multidict(arg1, arg2)
        mock_request.content_type = "application/x-www-form-urlencoded"

        controller = BaseController()
        controller._parse_request_params(mock_request)

        self.assertIsInstance(controller.request_params,
                              dict,
                              'self.request_params is not of type dict!')

        self.assertDictEqual(
            controller.request_params,
            expected_params,
            'parsed request_params do not match')

    @mock.patch('linotp.lib.base.request')
    @mock.patch('linotp.lib.base.BaseController.__init__', return_value=None)
    def test_jsondict_params(self, _mock_base, mock_request):
        """"
        check if global request.json_body gets parsed correctly
        """

        expected_params = {'k': ['1', '2'], 'l': 'Z'}

        mock_request.json_body = copy.deepcopy(expected_params)
        mock_request.content_type = "application/json"

        controller = BaseController()
        controller._parse_request_params(mock_request)

        self.assertIsInstance(controller.request_params,
                              dict,
                              'self.request_params is not of type dict!')

        self.assertDictEqual(
            controller.request_params,
            expected_params,
            'parsed request_params do not match')

    @mock.patch('linotp.lib.base.request')
    @mock.patch('linotp.lib.base.BaseController.__init__', return_value=None)
    def test_both_given(self, _mock_base, mock_request):
        """"
        check if json is give as content type the other params are ignored
        """

        expected_params = {'k': ['1', '2'], 'l': 'Z'}

        arg1 = [('k[]', '1'), ('k[]', '2')]
        arg2 = [('l', 'Z')]

        mock_request.json_body = copy.deepcopy(expected_params)
        mock_request.params = create_multidict(arg1, arg2)
        mock_request.content_type = "application/json"

        controller = BaseController()
        controller._parse_request_params(mock_request)

        self.assertIsInstance(controller.request_params,
                              dict,
                              'self.request_params is not of type dict!')

        self.assertDictEqual(
            controller.request_params,
            expected_params,
            'parsed request_params do not match')
