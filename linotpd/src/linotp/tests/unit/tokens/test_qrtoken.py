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
import json

from contextlib import nested
from linotp.lib.context import request_context_safety
from linotp.lib.context import request_context
from linotp.tokens.qrtoken.qrtoken import QrTokenClass
from mock import patch
from pylons import config


class FakeHSM(object):

    def isReady(self):
        return True

    def hmac_digest(self, key, data, algo):
        return 'foo'

fake_hsm_wrapper = {'obj': FakeHSM()}


# ---------------------------------------------------------------------------- -


class FakeTokenModel(object):

    def __init__(self):
        self.info_dict = {}

    def setInfo(self, json_str):
        self.info_dict = json.loads(json_str)

    def getSerial(self):
        return 'QRfoo123'

    def setType(self, type_):
        pass

    def getInfo(self):
        return json.dumps(self.info_dict)

    def get_encrypted_seed(self):
        return 'foo', 'bar'

# ---------------------------------------------------------------------------- -


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

    # ------------------------------------------------------------------------ -

    @patch('linotp.tokens.pushtoken.pushtoken.get_secret_key')
    def test_url_protocol_id(self, mocked_get_secret_key):

        """
        QRToken unittest: Test url protocol id customization
        """

        mocked_get_secret_key.return_value = 'X' * 64
        user_public_key = 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI='

        fake = FakeTokenModel()

        token = QrTokenClass(fake)
        token.addToTokenInfo('user_token_id', 1234)
        token.addToTokenInfo('user_public_key', user_public_key)

        with nested(patch.dict(config), request_context_safety()):

            if 'mobile_app_protocol_id' in config:
                del config['mobile_app_protocol_id']

            request_context['hsm'] = fake_hsm_wrapper

            # if no mobile_app_protocol_id is set, it should default
            # to lseqr

            message = 'here are the 2,750 quit you asked for. can i move' + \
                      'to OT I level now? - tom'

            url, _ = token.create_challenge_url(transaction_id='1234567890',
                                                content_type=0,
                                                message=message,
                                                callback_url='foo',
                                                callback_sms_number='+491234')

            self.assertTrue(url.startswith('lseqr://'))

        # -------------------------------------------------------------------- -

        fake = FakeTokenModel()
        token = QrTokenClass(fake)
        token.addToTokenInfo('user_token_id', 1234)
        token.addToTokenInfo('user_public_key', user_public_key)

        with nested(patch.dict(config, {'mobile_app_protocol_id': 'yolo'}),
                    request_context_safety()):

            request_context['hsm'] = fake_hsm_wrapper

            message = 'here are the 2,750 quit you asked for. can i move' + \
                      'to OT I level now? - tom'

            url, _ = token.create_challenge_url(transaction_id='1234567890',
                                                content_type=0,
                                                message=message,
                                                callback_url='foo',
                                                callback_sms_number='+491234')

            self.assertTrue(url.startswith('yolo://'))
