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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

import unittest

from mock import patch

from linotp.tokens.emailtoken import EmailTokenClass
from linotp.tokens.hmactoken import HmacTokenClass
from linotp.tokens.passwordtoken import PasswordTokenClass
from linotp.tokens.smstoken import SmsTokenClass
from linotp.tokens.totptoken import TimeHmacTokenClass
from linotp.tokens.yubikeytoken import YubikeyTokenClass

# ---------------------------------------------------------------------------- -


class FakeTokenModel(object):
    def __init__(self):
        self.LinOtpOtpLen = 8
        # emailtoken needs LinOtpCount variable to function correctly
        self.LinOtpCount = 0

    def setType(self, typ):
        self.type = typ

    def getSerial(self):
        return "FakeToken1"

    def getInfo(self):
        return ""

    def storeToken(self):
        pass

    def get_encrypted_seed(self):
        return b"", b""


def mock_send_email(self_obj):
    status = True
    status_message = "e-mail sent successfully"
    return status, status_message


def mock_send_email_fail(self_obj):
    status = False
    status_message = "sending e-mail failed"
    return status, status_message


Config_dict = {
    "TOTP_CHALLENGE_PROMPT": "Hello TOTP Prompt",
    "HMAC_CHALLENGE_PROMPT": "Hello HMAC Prompt",
    "YUBIKEY_CHALLENGE_PROMPT": "Hello yubikey Prompt",
    "PW_CHALLENGE_PROMPT": "Hello Password Prompt",
    "SMS_CHALLENGE_PROMPT": "Hello SMS Prompt",
    "EMAIL_CHALLENGE_PROMPT": "Hello E-Mail Prompt",
}


def mock_getFromConfig(key, fallback):
    return Config_dict.get(key, fallback)


class TestChallengePrompt(unittest.TestCase):
    """"""

    @patch("linotp.tokens.hmactoken.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.smstoken.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.smstoken.SmsTokenClass.loadLinOtpSMSValidTime")
    @patch("linotp.tokens.smstoken.SmsTokenClass.setValidUntil")
    @patch("linotp.tokens.smstoken.SmsTokenClass.submitChallenge")
    def tests_sms_token_challenge_prompt(
        self,
        mock_submitChallenge,
        mock_setValidUntil,
        mock_loadLinOtpSMSValidTime,
    ):
        mock_submitChallenge.return_value = True, "sms submitted"
        mock_setValidUntil.return_value = None
        mock_loadLinOtpSMSValidTime.return_value = 30

        prompt = Config_dict.get("SMS_CHALLENGE_PROMPT")

        sms_token = SmsTokenClass(FakeTokenModel())

        (_, message, _data, _) = sms_token.createChallenge(
            "131231231313123", options=None
        )

        assert message == prompt

        return

    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.hmactoken.getFromConfig", mock_getFromConfig)
    def tests_password_token_challenge_prompt(self):
        prompt = Config_dict.get("PW_CHALLENGE_PROMPT")

        pass_token = PasswordTokenClass(FakeTokenModel())

        (_, message, _data, _) = pass_token.createChallenge(
            "131231231313123", options=None
        )

        assert message == prompt

        return

    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    def tests_yubikey_token_challenge_prompt(self):
        prompt = Config_dict.get("YUBIKEY_CHALLENGE_PROMPT")

        yubi_token = YubikeyTokenClass(FakeTokenModel())

        (_, message, _data, _) = yubi_token.createChallenge(
            transactionid="131231231313123", options=None
        )

        assert message == prompt

        return

    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.hmactoken.getFromConfig", mock_getFromConfig)
    def tests_hmac_token_challenge_prompt(self):
        prompt = Config_dict.get("HMAC_CHALLENGE_PROMPT")

        hmac_token = HmacTokenClass(FakeTokenModel())

        (_, message, _data, _) = hmac_token.createChallenge(
            state="131231231313123", options=None
        )

        assert message == prompt

        return

    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.totptoken.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.hmactoken.getFromConfig", mock_getFromConfig)
    def tests_totp_token_challenge_prompt(self):
        prompt = Config_dict.get("TOTP_CHALLENGE_PROMPT")

        totp_token = TimeHmacTokenClass(FakeTokenModel())

        (_, message, _data, _) = totp_token.createChallenge(
            state="131231231313123", options=None
        )

        assert message == prompt

        return

    @patch(
        "linotp.tokens.emailtoken.EmailTokenClass._sendEmail", mock_send_email
    )
    @patch("linotp.tokens.hmactoken.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.emailtoken.getFromConfig", mock_getFromConfig)
    def tests_email_token_challenge_prompt(self):
        prompt = Config_dict.get("EMAIL_CHALLENGE_PROMPT")

        email_token = EmailTokenClass(FakeTokenModel())

        (_, message, _data, _) = email_token.createChallenge(
            transactionid="131231231313123", options=None
        )

        assert message == prompt

        return

    @patch(
        "linotp.tokens.emailtoken.EmailTokenClass._sendEmail",
        mock_send_email_fail,
    )
    @patch("linotp.tokens.hmactoken.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.base.getFromConfig", mock_getFromConfig)
    @patch("linotp.tokens.emailtoken.getFromConfig", mock_getFromConfig)
    def tests_failed_email_token_challenge_prompt(self):
        """To test that the prompt will be the output of
        the email provider rather than the custom message from the config
        """

        # this is the prompt that mock_send_email will produce
        prompt = "sending e-mail failed"

        email_token = EmailTokenClass(FakeTokenModel())

        (_, message, _data, _) = email_token.createChallenge(
            transactionid="131231231313123", options=None
        )

        assert message == prompt

        return
