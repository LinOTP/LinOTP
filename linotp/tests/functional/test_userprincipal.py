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
Verify LinOTP for UserPrincipal (user@domain) authentication

the test will create a static-password token, and
will try to verify the user in different situations.
"""

from linotp.tests import TestController


class TestUserPrincipalController(TestController):
    """verify the handling of users in UserPrincipal style"""

    def setUp(self):
        self.tokens = {}

        params = {"splitAtSign": True}
        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response.body

        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        params = {"splitAtSign": True}
        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response.body

        return TestController.tearDown(self)

    def test_userprincipal(self):
        """
        Verify LinOTP for UserPrincipal (user@domain) authentication

        the test will create a static-password token, and
        will try to verify the user in different situations.

        """

        params = {"splitAtSign": False}
        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response, response

        user = "pass@user"
        pin = "1234"
        realm = "myDefRealm"
        serial = "F722362"
        # Initialize authorization (we need authorization in
        # token creation/deletion)...

        params = {
            "realm": realm,
            "serial": serial,
            "pin": pin,
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "type": "spass",
        }

        # Create test token...
        response = self.make_admin_request("init", params=params)
        assert serial in response, response

        # although not needed, we assign token...
        params = {"serial": serial, "user": user, "realm": realm}
        response = self.make_admin_request("assign", params=params)
        assert '"status": true' in response, response

        params = {
            "serial": serial,
        }

        response = self.make_admin_request("enable", params=params)
        assert '"status": true' in response, response

        # test user-principal authentication
        params = {"user": user, "pass": pin, "realm": realm}

        response = self.make_validate_request("check", params=params)

        params = {
            "serial": serial,
        }

        response = self.make_admin_request("remove", params=params)


# eof
