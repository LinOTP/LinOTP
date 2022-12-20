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


"""Test for various policy aspects:
    - adminstrative permissions
    - authorization
    - authentication
    - selfservice
    - enrollment
"""


import copy
import logging
import re

import pytest

from . import TestPoliciesBase

log = logging.getLogger(__name__)


class TestRealmPolicies(TestPoliciesBase):
    def setUp(self):
        """setup the test controller"""
        TestPoliciesBase.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """clean up after the tests"""
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestPoliciesBase.tearDown(self)
        return

    def test_realms_allowed_by_admin_show(self):
        """
        If an admin has has any permissions granted via a policy, he is
        allowed to list the tokens of that realm. Thus admin/show is a
        base permission which is granted in addition to all defined actions
        for that realm.

        The test enrolls tokens in different realms. For one realm the
        adminR1 is explicitly only allowed to enroll token for that realm
        'myOtherRealm'. But as the 'admin/show' permission is granted implicit
        he is allowed to list the tokens in that realm as well.
        """

        policies = [
            {
                "name": "admin_show",
                "scope": "admin",
                "realm": "myDefRealm",
                "action": "show",
                "user": "adminR1",
                "client": "",
            },
            {
                "name": "admin_init",
                "scope": "admin",
                "realm": "myOtherRealm",
                "action": "init",
                "user": "adminR1",
                "client": "",
            },
            {
                "name": "admin_all",
                "scope": "admin",
                "realm": "myMixRealm",
                "action": "*",
                "user": "adminR1",
                "client": "",
            },
            {
                "name": "superadmin_init",
                "scope": "admin",
                "realm": "*",
                "action": "*",
                "user": "adminR2",
                "client": "",
            },
        ]

        # set policies
        for pol in policies:
            response = self.make_system_request(
                action="setPolicy", params=pol, auth_user="superadmin"
            )

            assert response.json["result"]["status"], response
            assert response.json["result"]["value"][
                "setPolicy %s" % pol["name"]
            ], response

        # create two tokens and set them in different realms
        seed = "154bf508c52f3048fcf9cf721bbb892637f5e348"

        for serial, realm in [
            ("oathDef", "myDefRealm"),
            ("oathOther", "myOtherRealm"),
            ("oathMix", "myMixRealm"),
        ]:
            parameters = {
                "serial": serial,
                "type": "hmac",
                "otpkey": seed,
                "pin": "something",
            }
            response = self.make_admin_request(
                action="init", params=parameters, auth_user="adminR2"
            )
            assert response.json["result"]["status"], response

            params = {"serial": serial, "realms": realm}
            response = self.make_admin_request(
                action="tokenrealm", params=params, auth_user="adminR2"
            )
            assert response.json["result"]["value"] == 1, response

        response = self.make_admin_request(action="show", auth_user="adminR1")

        tokens = response.json["result"]["value"]["data"]
        serials = [token["LinOtp.TokenSerialnumber"] for token in tokens]

        assert (
            "oathDef" in serials
        ), "oathDef is in realm myDefRealm and should be listed"
        assert (
            "oathMix" in serials
        ), "oathMix is in realm myMixRealm and should be listed"
        assert (
            "oathOther" in serials
        ), "oathOther is in realm myDefRealm and should be listed"
