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

from linotp.lib.security.provider import SecurityProvider

from mock import patch


class TestHSMPool(unittest.TestCase):
    """
    Unit test to check the exception handling for createHSMPool
    """

    @patch('linotp.lib.security.provider.SecurityProvider.loadSecurityModule')
    @patch('linotp.lib.security.provider.SecurityProvider._getHsmPool_')
    @patch('linotp.lib.security.provider.SecurityProvider.__init__')

    def test_create_hsm_pool(self,
                             mock_init,
                             mock_get_hsm_pool,
                             mock_load_security_module):

        mock_init.return_value = None
        mock_get_hsm_pool.return_value = None

        mock_load_security_module.side_effect = Exception('Mocked Exception to be caught')

        # hook for local provider test
        sec_prov = SecurityProvider()
        sec_prov.config = {'default': {
            'crypted': 'FALSE',
            'module': 'linotp.lib.security.default.DefaultSecurityModule',
            'poolsize': 20}}

        sec_prov.hsmpool = {'default': ''}
        sec_prov.createHSMPool('default', None, None)

        return True
