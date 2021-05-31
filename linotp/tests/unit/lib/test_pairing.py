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

import pytest
import unittest

from linotp.flap import config
from linotp.lib.pairing import generate_pairing_url
from mock import patch


@pytest.mark.usefixtures("app")
class PairingUnitTestCase(unittest.TestCase):

    @patch('linotp.lib.pairing.get_secret_key')
    @patch('linotp.lib.pairing.get_public_key')
    @patch('linotp.lib.pairing.get_dh_secret_key')
    def test_protocol_id(self,
                         mocked_get_secret_key,
                         mocked_get_public_key,
                         mocked_get_dh_secret_key):

        """
        test if pairing urls get generated with correct custom protocol ids
        """

        mocked_get_secret_key.return_value = b'X' * 64
        mocked_get_dh_secret_key.return_value = b'X' * 64
        mocked_get_public_key.return_value = b'X' * 32

        with patch.dict(config):

            # if configuration entry is not present,
            # protocol id should be lseqr

            if 'mobile_app_protocol_id' in config:
                del config['mobile_app_protocol_id']

            url = generate_pairing_url(token_type='qr',
                                       partition=1,
                                       serial='QRfoo',
                                       callback_url='foo')

            assert url.startswith('lseqr://')

        # -------------------------------------------------------------------- -

        with patch.dict(config, {'mobile_app_protocol_id': 'yolo'}):

            url = generate_pairing_url(token_type='qr',
                                       partition=1,
                                       serial='QRfoo',
                                       callback_url='foo')

            assert url.startswith('yolo://')
