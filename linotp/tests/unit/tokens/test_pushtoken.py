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

import unittest
import json
import base64

import pytest

from pysodium import crypto_sign_keypair

from linotp.flap import config

from mock import patch

from linotp.lib.context import request_context_safety
from linotp.lib.context import request_context
from linotp.tokens.pushtoken.pushtoken import PushTokenClass


class FakeHSM(object):
    def isReady(self):
        return True

    def hmac_digest(self, key, data, algo):
        return "foo"

    def decryptPassword(self, crypted):
        return 2 * "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI" + "=="


fake_hsm_wrapper = {"obj": FakeHSM()}

# -------------------------------------------------------------------------- --


class FakeTokenModel(object):
    def __init__(self):
        self.info_dict = {}

    def setInfo(self, json_str):
        self.info_dict = json.loads(json_str)

    def getSerial(self):
        return "QRfoo123"

    def setType(self, type_):
        pass

    def getInfo(self):
        return json.dumps(self.info_dict)

    def get_encrypted_seed(self):
        return "foo", "bar"


# -------------------------------------------------------------------------- --


class PushTokenClassUnitTestCase(object):

    # ---------------------------------------------------------------------- --

    @patch("linotp.tokens.pushtoken.pushtoken.get_secret_key")
    def test_url_protocol_id(self, base_app, mocked_get_secret_key):
        """ PUSHTOKEN: Test url protocol id customization """

        public_key, secret_key = crypto_sign_keypair()

        mocked_get_secret_key.return_value = secret_key
        user_public_key = base64.b64encode(public_key)

        fake = FakeTokenModel()

        token = PushTokenClass(fake)
        token.addToTokenInfo("partition", 0)
        token.addToTokenInfo("user_token_id", 123)
        token.addToTokenInfo("user_dsa_public_key", user_public_key)

        with base_app.test_request_context():

            if "mobile_app_protocol_id" in config:
                del config["mobile_app_protocol_id"]

            request_context["hsm"] = fake_hsm_wrapper

            # if no mobile_app_protocol_id is set, it should default
            # to lseqr

            message = (
                "here are the 2,750 quit you asked for. can i move"
                + "to OT I level now? - tom"
            )

            url, _ = token.create_challenge_url(
                transaction_id="1234567890",
                content_type=0,
                message=message,
                callback_url="foo",
            )

            assert url.startswith("lseqr://")

        # ------------------------------------------------------------------ --

        fake = FakeTokenModel()

        token = PushTokenClass(fake)
        token.addToTokenInfo("partition", 0)
        token.addToTokenInfo("user_token_id", 123)
        token.addToTokenInfo("user_dsa_public_key", user_public_key)

        with base_app.test_request_context():
            config["mobile_app_protocol_id"] = "yolo"

            request_context["hsm"] = fake_hsm_wrapper

            message = (
                "here are the 2,750 quit you asked for. can i move"
                + "to OT I level now? - tom"
            )

            url, _ = token.create_challenge_url(
                transaction_id="1234567890",
                content_type=0,
                message=message,
                callback_url="foo",
            )

            assert url.startswith("yolo://")


# eof #
