# -*- coding: utf-8 -*-
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

import unittest
from mock import patch, ANY

from linotp.lib import resolver

class TestGetResolverList(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestGetResolverList, cls).setUpClass()

    @patch('linotp.lib.resolver.get_resolver_types', return_value=['test'])
    def _do_readonly_param_test(self, param, is_invalid, expected_readonly, mock_get_types):
        """
        Call getresolverlist with given configuration
        """

        conf = {
            'linotp.test.name.UnitTestResolver': 'UnitTestResolver',
            'linotp.test.readonly.UnitTestResolver': param,
            }

        with patch('linotp.lib.resolver.context', return_value=conf) as mock_context:
            mock_context.get.return_value = conf
            with patch('linotp.lib.resolver.log') as mock_log:
                ret = resolver.getResolverList()

                if is_invalid:
                    # Invalid parameter will log a message
                    mock_log.info.assert_called_with(
                        "Failed to convert 'readonly' attribute %r:%r", ANY, param)

                # If readonly, the resulting resolver has config key=readonly, value=True
                # If not readonly, the resulting resolver does not have the readonly key
                r = ret['UnitTestResolver']
                if expected_readonly:
                    assert r['readonly'] == True
                else:
                    assert 'readonly' not in r

    def test_get_resolverlist_with_invalid_readonly(self):
        """
        test: an invalid readonly conf entry will raise an exception
        """
        self._do_readonly_param_test('truly', True, None)

    def test_get_resolverlist_readonly_param(self):
        """
        check true/false values are correctly interpreted
        """
        self._do_readonly_param_test('', False, False)
        self._do_readonly_param_test('true', False, True)
        self._do_readonly_param_test('false', False, False)
