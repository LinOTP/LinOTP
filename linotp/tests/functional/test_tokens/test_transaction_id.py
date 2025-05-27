# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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


"""check if last access configuration does work"""

from linotp.tests import TestController


class TestTransactionId(TestController):
    """check for the transaction id handling"""

    def setUp(self):
        TestController.setUp(self)

        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()

        return super().tearDown()

    def test_multi_transaction_id_length(self):
        """check that the min transactionid length for a validation request

        test setup:
        * setup challenge response policy
        * enroll one tokens
        * trigger challenges

        test cases:
        * 1. arbitrary cutted transaction id => fail
        * 2. parent transaction id as if it would be a subtransaction => success

        """
        # setup test

        # a. enable challenge response for pw tokens
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

        # b. enroll 2 tokens: AToken and BToken
        tokens = {"AToken": "123", "BToken": "321"}

        for serial, secret in tokens.items():
            params = {
                "serial": serial,
                "type": "pw",
                "otpkey": secret,
                "pin": "pin",
                "user": "root",
            }

            response = self.make_admin_request("init", params=params)
            assert serial in response, response.body

        # now trigger challenge via same pin
        params = {"user": "root", "pass": "pin"}
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]

        # grab the challenge for token A

        challenges = response.json["detail"]["challenges"]
        challenge_a = challenges["AToken"]

        transaction_id = challenge_a["transactionid"]

        # run the test cases

        # 1. arbitrary cut transaction id
        params = {
            "transactionid": transaction_id[:-5],
            "pass": tokens["AToken"],
            "user": "root",
        }
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]
        assert not response.json["result"]["value"]

        # 2. parent transaction id as a subtransaction => success

        params = {
            "transactionid": transaction_id[:-3],
            "pass": tokens["AToken"],
            "user": "root",
        }
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]
        assert response.json["result"]["value"]

    def test_single_transaction_id_length(self):
        """check that the min transactionid length for a validation request

        test setup:
        * setup challenge response policy
        * enroll one tokens
        * trigger challenges

        test cases:
        * 1. arbitrary cutted transaction id => fail
        * 2. parent transaction id as if it would be a subtransaction => fail
        # 3. full transaction id => success
        """

        # setup the tests

        # a. enable challenge response for pw tokens
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

        # b. enroll the token

        serial = "AToken"
        secret = "123"

        params = {
            "serial": serial,
            "type": "pw",
            "otpkey": secret,
            "pin": "pin",
            "user": "root",
        }

        response = self.make_admin_request("init", params=params)
        assert serial in response, response.body

        # now trigger challenge via same pin
        params = {"user": "root", "pass": "pin"}
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]
        transaction_id = response.json["detail"]["transactionid"]

        # run the test cases

        # 1. arbitrary cutted transaction id => fail
        params = {
            "transactionid": transaction_id[:-5],
            "pass": secret,
            "user": "root",
        }
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]
        assert not response.json["result"]["value"]

        # 2. parent transaction id as if it would be a subtransaction => fail

        params = {
            "transactionid": transaction_id[:-3],
            "pass": secret,
            "user": "root",
        }
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]
        assert not response.json["result"]["value"]

        # 3. full transaction id => success

        params = {
            "transactionid": transaction_id,
            "pass": secret,
            "user": "root",
        }
        response = self.make_validate_request("check", params=params)

        assert response.json["result"]["status"]
        assert response.json["result"]["value"]
