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


"""verify that the failcounter is not incremented twice"""

import json
from datetime import datetime

from linotp.tests import TestController


class TestDuplicateFailcounterIncrement(TestController):
    """"""

    def setUp(self):
        resp = TestController.setUp(self)

        self.create_common_resolvers()
        self.create_common_realms()

        return resp

    def test_duplicate_failcounter_increment(self):
        """check that last_access does work with time format expressions"""

        # ------------------------------------------------------------------ --

        # define the authentication policy so that challenge response is
        # active for all tokens

        params = {
            "name": "duplicate_inc",
            "scope": "authentication",
            "active": True,
            "action": "challenge_response=*,",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response.body, response.body

        # ------------------------------------------------------------------ --

        # enroll tokens - one only challenge response, one for both mods

        params = {
            "user": "root",
            "serial": "roots_email_token",
            "type": "email",
            "email_address": "root@home",
            "pin": "123!",
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        params = {
            "user": "root",
            "serial": "roots_hmac_token",
            "genkey": "1",
            "type": "hmac",
            "pin": "123!",
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # now run a validate check on pin base

        params = {
            "user": "root",
            "pass": "123!",
        }

        response = self.make_validate_request("check", params=params)
        assert '"value": false' in response

        # ------------------------------------------------------------------ --

        # have a look on the token

        params = {
            "user": "root",
        }

        response = self.make_admin_request("show", params=params)
        jresp = json.loads(response.body)

        failcounters = []

        data = jresp["result"]["value"]["data"]
        for entry in data:
            failcounters.append(entry["LinOtp.FailCount"])

        assert failcounters[0] == failcounters[1]

        self.delete_all_token()
        return
