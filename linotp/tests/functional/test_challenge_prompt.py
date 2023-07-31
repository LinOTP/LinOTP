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

"""
  Test the Challenge Prompt
"""

import binascii
import json
import time

import pytest
from mock import patch

import linotp.provider.smsprovider.HttpSMSProvider
from linotp.lib.HMAC import HmacOtp
from linotp.tests import TestController


def calcOTP(key, counter=0, digits=6, typ=None):
    """
    as we have to use this method in a not class related function
    this function is extracted

    :param key: the otpkey secret
    :param counter: the related counter
    :param digits: the number of to be returned digits

    :return: the otp value as string
    """
    htoken = HmacOtp(digits=digits)
    if typ == "totp":
        timestep = 30
        time.sleep(timestep + 1)
        counter = int((time.time() / timestep) + 0.5)

    otp = htoken.generate(counter=counter, key=binascii.unhexlify(key))

    return otp


# patch our submit Message
def mocked_submitMessage_request(SMS_Object, *argparams, **kwparams):
    # this hook is defined to grep the otp and make it globaly available
    global SMS_MESSAGE_OTP
    SMS_MESSAGE_OTP = argparams

    # we call here the original sms submitter - as we are a functional test
    # res = SMS_Object._submitMessage(*argparams)
    res = True

    return res


@pytest.mark.nightly
class TestChallengePrompt(TestController):
    """Tests for ChallengePrompt of different tokens

    :note: The test for email_challenge_prompt is
    being done in the test_email_token
    """

    sms_url = "http://localhost:%d/testing/http2sms" % 5001

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def init_yubikey_otps(self, public_uid):
        self.valid_yubikey_otps = [
            public_uid + "fcniufvgvjturjgvinhebbbertjnihit",
            public_uid + "tbkfkdhnfjbjnkcbtbcckklhvgkljifu",
            public_uid + "ktvkekfgufndgbfvctgfrrkinergbtdj",
            public_uid + "jbefledlhkvjjcibvrdfcfetnjdjitrn",
            public_uid + "druecevifbfufgdegglttghghhvhjcbh",
            public_uid + "nvfnejvhkcililuvhntcrrulrfcrukll",
            public_uid + "kttkktdergcenthdredlvbkiulrkftuk",
            public_uid + "hutbgchjucnjnhlcnfijckbniegbglrt",
            public_uid + "vneienejjnedbfnjnnrfhhjudjgghckl",
            public_uid + "krgevltjnujcnuhtngjndbhbiiufbnki",
            public_uid + "kehbefcrnlfejedfdulubuldfbhdlicc",
            public_uid + "ljlhjbkejkctubnejrhuvljkvglvvlbk",
            public_uid + "eihtnehtetluntirtirrvblfkttbjuih",
        ]
        return

    def init_yubikey_token(
        self,
        serialnum="01382015",
        yubi_slot=1,
        otpkey="9163508031b20d2fbb1868954e041729",
        public_uid="ecebeeejedecebeg",
        use_public_id=False,
        user=None,
    ):
        serial = "UBAM%s_%s" % (serialnum, yubi_slot)

        params = {
            "type": "yubikey",
            "serial": serial,
            "otpkey": otpkey,
            "description": "Yubikey enrolled in functional tests",
        }

        if not use_public_id:
            params["otplen"] = 32 + len(public_uid)
        else:
            params["public_uid"] = public_uid

        if user:
            params["user"] = user

        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, "Response: %r" % response

        # setup the otp values, that we check against
        self.init_yubikey_otps(public_uid)

        return serial

    def test_yubikey_challenge_prompt(self):
        """
        Enroll and verify otp for the Yubikey in yubico (AES) mode

        test with public_uid and without public_uid

        """
        params = {
            "name": "ch_resp",
            "realm": "*",
            "action": "challenge_response=*, ",
            "user": "*",
            "active": True,
            "scope": "authentication",
        }
        response = self.make_system_request("setPolicy", params)
        assert "false" not in response, response

        public_uid = "ecebeeejedecebeg"
        user = "passthru_user1"

        serial = self.init_yubikey_token(public_uid=public_uid, user=user)
        pin = "1234!"

        params = {"serial": serial, "pin": pin}
        response = self.make_admin_request("set", params)

        # --------------------------------------------------------------- --

        # define a system defined challenge prompt

        prompt = "How are you?"

        params = {"YUBIKEY_CHALLENGE_PROMPT": prompt}
        response = self.make_system_request("setConfig", params)

        assert prompt in response, response

        # --------------------------------------------------------------- --

        # trigger the challenge request

        params = {"user": user, "pass": pin}
        response = self.make_validate_request("check", params=params)

        assert prompt in response, response

        # --------------------------------------------------------------- --

        # unset the config entry and check if the prompt is not more
        # in the challenge prompt

        params = {"key": "YUBIKEY_CHALLENGE_PROMPT"}
        response = self.make_system_request("delConfig", params)

        assert (
            '"delConfig YUBIKEY_CHALLENGE_PROMPT": true' in response
        ), response

        # --------------------------------------------------------------- --

        self.delete_all_token()
        self.delete_policy("ch_resp")

        return

    def test_hmac_challenge_prompt(self):
        """
        Challenge Response Test: HMAC tokens with challenge prompt
        """

        # --------------------------------------------------------------- --

        # define challenge response policy

        params = {
            "name": "ch_resp",
            "scope": "authentication",
            "action": "challenge_response=*, ",
            "active": True,
            "user": "*",
            "realm": "myDefRealm",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        # --------------------------------------------------------------- --

        # create hmac token

        counter = 0
        serial = "HMAC_TEST_TOKEN_1"
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        params = {
            "otpkey": otpkey,
            "pin": "shortpin",
            "user": "passthru_user1",
            "typ": "hmac",
            "serial": serial,
        }

        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, response

        # --------------------------------------------------------------- --

        # trigger a challenge and answer it correctly

        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.make_validate_request(action="check", params=params)
        assert '"value": false' in response, response
        assert '"transactionid":' in response, response

        # --------------------------------------------------------------- --

        # in the response we expect an transaction reference (=state)
        # and a reply message message

        body = json.loads(response.body)
        state = body.get("detail", {}).get("transactionid", None)
        assert state is not None, response

        # --------------------------------------------------------------- --

        # submit a otp only challenge response

        otp = calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": otp}
        params["transactionid"] = state
        response = self.make_validate_request(action="check", params=params)
        assert '"value": true' in response, response

        # --------------------------------------------------------------- --

        # define a system defined challenge prompt

        prompt = "How are you?"

        params = {"HMAC_CHALLENGE_PROMPT": prompt}
        response = self.make_system_request("setConfig", params)

        assert prompt in response, response

        # --------------------------------------------------------------- --

        # submit a pin only request - to trigger a challenge

        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.make_validate_request(action="check", params=params)
        assert '"value": false' in response, response
        assert '"transactionid":' in response, response
        assert prompt in response, response

        # --------------------------------------------------------------- --

        # unset the config entry and check if the prompt is not more
        # in the challenge prompt

        params = {"key": "HMAC_CHALLENGE_PROMPT"}
        response = self.make_system_request("delConfig", params)

        assert '"delConfig HMAC_CHALLENGE_PROMPT": true' in response, response

        # --------------------------------------------------------------- --

        # submit a pin only request - to trigger a challenge where there is
        # no more part of the challenge reply

        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.make_validate_request(action="check", params=params)
        assert '"value": false' in response, response
        assert '"transactionid":' in response, response
        assert prompt not in response, response

        # --------------------------------------------------------------- --

        # cleanup

        self.delete_token(serial)

        self.delete_policy(name="ch_resp")

        return

    @patch.object(
        linotp.provider.smsprovider.HttpSMSProvider.HttpSMSProvider,
        "submitMessage",
        mocked_submitMessage_request,
    )
    def test_sms_challenge_prompt(self):
        """
        Challenge Response Test: sms token challenge with otppin=1 + otppin=2
        """

        params = {
            "SMSProvider": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }
        _response = self.make_system_request(action="setConfig", params=params)

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "SMSProviderConfig": json.dumps(sms_conf),
        }
        response = self.make_system_request(action="setConfig", params=params)
        assert '"status": true' in response, response

        params = {"name": "imported_default", "type": "sms"}
        response = self.make_system_request(
            "setDefaultProvider", params=params
        )

        counter = 0
        serial = "SMS_TOKEN_01"
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        params = {
            "serial": serial,
            "otpkey": otpkey,
            "user": "passthru_user1",
            "pin": "shortpin",
            "type": "sms",
            "phone": "12345",
        }

        response = self.make_admin_request(action="init", params=params)
        assert '"value": true' in response, response

        # --------------------------------------------------------------- --

        # define a system defined challenge prompt

        prompt = "How are you sms challenge?"
        params = {"SMS_CHALLENGE_PROMPT": prompt}
        response = self.make_system_request("setConfig", params)

        assert prompt in response, response

        # --------------------------------------------------------------- --

        # run the authentication with new prompt

        params = {"serial": serial, "pass": "shortpin"}
        response = self.make_validate_request("check_s", params)
        assert prompt in response, response

        # --------------------------------------------------------------- --

        # unset the config entry and check if the prompt is not more
        # in the challenge prompt

        params = {"key": "SMS_CHALLENGE_PROMPT"}
        response = self.make_system_request("delConfig", params)

        assert '"delConfig SMS_CHALLENGE_PROMPT": true' in response, response
        # --------------------------------------------------------------- --

        self.delete_token(serial)
        return

    def tests_password_token(self):
        """
        test the password token with a different prompt
        """
        # --------------------------------------------------------------- --

        # define challenge response policy

        params = {
            "name": "ch_resp",
            "scope": "authentication",
            "action": "challenge_response=*, ",
            "active": True,
            "user": "*",
            "realm": "myDefRealm",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        # --------------------------------------------------------------- --

        # define a system defined challenge prompt

        prompt = "How are you?"
        params = {"PW_CHALLENGE_PROMPT": prompt}
        response = self.make_system_request("setConfig", params)

        assert prompt in response, response

        # --------------------------------------------------------------- --

        # create the password token
        params = {
            "serial": "TPW",
            "user": "root",
            "pin": "pin",
            "otpkey": "123456",
            "type": "pw",
            "user": "passthru_user1",
        }

        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, response

        # --------------------------------------------------------------- --

        # trigger the challenge with a validate request

        params = {"user": "passthru_user1", "pass": "pin"}

        response = self.make_validate_request("check", params=params)
        assert prompt in response, response

        # --------------------------------------------------------------- --

        # unset the config entry and check if the prompt is not more
        # in the challenge prompt

        params = {"key": "PW_CHALLENGE_PROMPT"}
        response = self.make_system_request("delConfig", params)

        assert '"delConfig PW_CHALLENGE_PROMPT": true' in response, response
        # --------------------------------------------------------------- --

        self.delete_all_token()
        self.delete_policy(name="ch_resp")

        return
