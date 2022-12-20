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

from linotp.tokens.hmactoken import HmacTokenClass
from linotp.tokens.totptoken import TimeHmacTokenClass
from linotp.tokens.yubikeytoken import YubikeyTokenClass
from linotp.tokens.passwordtoken import PasswordTokenClass
from linotp.tokens.smstoken import SmsTokenClass

# ---------------------------------------------------------------------------- -

class FakeTokenModel(object):

    def __init__(self):
        pass

    def setType(self, typ):
        self.type = typ

    def getSerial(self):
        return "FakeToken1"


Config_dict = {
    'TOTP_CHALLENGE_PROMPT': "Hello TOTP Prompt",
    'HMAC_CHALLENGE_PROMPT': "Hello HMAC Prompt",
    'YUBIKEY_CHALLENGE_PROMPT': "Hello yubikey Prompt",
    'PW_CHALLENGE_PROMPT': "Hello Password Prompt",
    'SMS_CHALLENGE_PROMPT': "Hello SMS Prompt",
}


def mock_getFromConfig(key, fallback):
    return Config_dict.get(key, fallback)


class TestChallengePrompt(unittest.TestCase):
    """
    """

    @patch('linotp.tokens.hmactoken.getFromConfig', mock_getFromConfig)
    @patch('linotp.tokens.smstoken.getFromConfig', mock_getFromConfig)
    @patch('linotp.tokens.smstoken.SmsTokenClass.loadLinOtpSMSValidTime')
    @patch('linotp.tokens.smstoken.SmsTokenClass.setValidUntil')
    @patch('linotp.tokens.smstoken.SmsTokenClass.submitChallenge')
    def tests_sms_token_challenge_prompt(self,
                                         mock_submitChallenge,
                                         mock_setValidUntil,
                                         mock_loadLinOtpSMSValidTime
                                         ):

        mock_submitChallenge.return_value = True, 'sms submitted'
        mock_setValidUntil.return_value = None
        mock_loadLinOtpSMSValidTime.return_value = 30

        prompt = Config_dict.get('SMS_CHALLENGE_PROMPT')

        sms_token = SmsTokenClass(FakeTokenModel())

        (_, message, _data, _) = sms_token.createChallenge(
                                    "131231231313123",
                                    options=None)

        assert message == prompt

        return

    @patch('linotp.tokens.hmactoken.getFromConfig', mock_getFromConfig)
    def tests_password_token_challenge_prompt(self):

        prompt = Config_dict.get('PW_CHALLENGE_PROMPT')

        pass_token = PasswordTokenClass(FakeTokenModel())

        (_, message, _data, _) = pass_token.createChallenge(
                                    "131231231313123",
                                    options=None)

        assert message == prompt

        return

    @patch('linotp.tokens.base.getFromConfig', mock_getFromConfig)
    def tests_yubikey_token_challenge_prompt(self):

        prompt = Config_dict.get('YUBIKEY_CHALLENGE_PROMPT')

        yubi_token = YubikeyTokenClass(FakeTokenModel())

        (_, message, _data, _) = yubi_token.createChallenge(
                                    transactionid="131231231313123",
                                    options=None)

        assert message == prompt

        return

    @patch('linotp.tokens.hmactoken.getFromConfig', mock_getFromConfig)
    def tests_hmac_token_challenge_prompt(self):

        prompt = Config_dict.get('HMAC_CHALLENGE_PROMPT')

        hmac_token = HmacTokenClass(FakeTokenModel())

        (_, message, _data, _) = hmac_token.createChallenge(
                                    state="131231231313123",
                                    options=None)

        assert message == prompt

        return

    @patch('linotp.tokens.totptoken.getFromConfig', mock_getFromConfig)
    @patch('linotp.tokens.hmactoken.getFromConfig', mock_getFromConfig)
    def tests_totp_token_challenge_prompt(self):

        prompt = Config_dict.get('TOTP_CHALLENGE_PROMPT')

        totp_token = TimeHmacTokenClass(FakeTokenModel())

        (_, message, _data, _) = totp_token.createChallenge(
                                state="131231231313123",
                                options=None)

        assert message == prompt

        return

