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
from linotp.model.meta import Session

from linotp.controllers.system import SystemController


class TestSetResolver(unittest.TestCase):

    @patch('linotp.controllers.system.BaseController.__init__', return_value=None)
    def setUp(self, mock_base):
        unittest.TestCase.setUp(self)
        self.system = SystemController()

    def tearDown(self):
        Session.remove()

    @patch('linotp.controllers.system.getResolverList', return_value=[])
    @patch('linotp.controllers.system.request')
    @patch('linotp.controllers.system.prepare_resolver_parameter')
    @patch('linotp.controllers.system._')
    @patch('linotp.controllers.system.defineResolver')
    def set_resolver(self, params, mock_define_resolver, mock_translate, mock_prepare, mock_request, mock_resolverlist):
        # Call set resolver with given parameters

        params['name'] = 'UnitTestResolver'

        # prepare_request_params simply returns the parameters unchanged
        mock_prepare.side_effect = lambda new_resolver_name, param, previous_name: (param, False, False)

        with patch('linotp.controllers.system.sendError') as mock_senderror:
            with patch('linotp.controllers.system.sendResult') as mock_sendresult:
                # sendError returns the exception
                mock_senderror.side_effect = lambda response, exx: exx
                mock_sendresult.side_effect = lambda response, obj, *args: obj
                self.system.request_params = params
                ret = self.system.setResolver()

        return ret

    def test_set_resolver_readonly_param_invalid(self):
        expected_message = "Failed to convert attribute 'readonly' to a boolean value! 'truly'"
        ret = self.set_resolver({'readonly': 'truly'})
        self.assertEqual(ret.message, expected_message, "Unexpected result:\n Ret:%s\n Expected:%s" % (ret.message, expected_message))

    def test_set_resolver_readonly_param_empty(self):
        ret = self.set_resolver({'readonly': ''})
        assert ret, "setResolver with empty readonly parameter should succeed. Returned:%s" % ret
