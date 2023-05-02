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

from linotp.lib.crypto.utils import createActivationCode
from linotp.tests import TestController

from . import OcraOtp


class UserserviceOcra2TokenTest(TestController):
    """
    support userservice api endpoint to enroll an ocra2 token
    """

    def setUp(self):
        # clean setup
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        TestController.setUp(self)

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)

    def test_enroll_ocra2(self):
        """verify userservice enrollment and activation of an ocra2 token"""

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        # ------------------------------------------------------------------ --

        # setup the permissions

        policy = {
            "name": "T1",
            "action": "activate_OCRA2, enrollOCRA2, delete, ",
            "user": " passthru.*.myDefRes:",
            "realm": "*",
            "scope": "selfservice",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # enroll the ocra2 token - first part

        ocra_otp = OcraOtp()

        params = {
            "genkey": "1",
            "description": "self enrolled",
            "type": "ocra2",
            "sharedsecret": "1",
        }
        response = self.make_userselfservice_request(
            "enroll", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "<img" in response
        serial = response.json["detail"]["serial"]

        # update state to our ocra otp object

        ocra_otp.init_1(response)

        # ------------------------------------------------------------------ --

        # enroll the ocra2 token - second part

        activationcode = createActivationCode()

        params = {
            "activationcode": activationcode,
            "type": "ocra2",
            "genkey": "1",
            "serial": serial,
        }

        response = self.make_userselfservice_request(
            "activateocratoken",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )

        assert response.json["result"]["status"], response.body

        # update state to our ocra otp object and extract challenge and transid

        (challenge, transid) = ocra_otp.init_2(response, activationcode)

        # ------------------------------------------------------------------ --

        # finish the roll out by using the dedicated userservice endpoint

        params = {
            "serial": serial,
            "transactionid": transid,
            "pass": ocra_otp.callcOtp(challenge),
            "type": "ocra2",
        }

        response = self.make_userselfservice_request(
            "finishocra2token",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )

        assert "false" not in response, response


# eof
