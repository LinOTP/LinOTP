# -*- coding: utf-8 -*-
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

import unittest
import json

from linotp.tokens.qrtoken.qrtoken import QrTokenClass


class FakeTokenModel(object):

    def __init__(self):
        self.info_dict = {}

    def setInfo(self, json_str):
        self.info_dict = json.loads(json_str)

    def setType(self, type_):
        pass

    def getInfo(self):
        return json.dumps(self.info_dict)

class QRTokenClassUnitTestCase(unittest.TestCase):

    def test_unpair(self):

        """ QRToken unittest: checking if unpairing works """

        fake = FakeTokenModel()

        token = QrTokenClass(fake)

        token.addToTokenInfo('user_token_id', 'bar')
        token.addToTokenInfo('user_public_key', 'foo')
        token.change_state('baz')

        token.unpair()

        self.assertNotIn('user_token_id', fake.info_dict)
        self.assertNotIn('user_public_key', fake.info_dict)
        self.assertEqual('pairing_url_sent', token.current_state)
