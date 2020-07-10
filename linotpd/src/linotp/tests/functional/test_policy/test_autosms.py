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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

""" unit test for autosms policy """

import pytest

from linotp.lib.context import request_context as context
from linotp.lib.policy import get_auth_AutoSMSPolicy
from linotp.lib.user import getUserFromParam
from linotp.tests import TestController


##########################################################################
#
#  AutoSMS


class TestAutoSmsPolicy(TestController):
    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        # self.initToken()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    @pytest.fixture(autouse=True)
    def set_policy_fixture(self, set_policy):  # pylint: disable=redefined-outer-name
        self.set_policy = set_policy  # pylint: disable=attribute-defined-outside-init

    def do_autosms_test(self, policy, user, client_ip, expected_result):
        new_policy = {
            "name": "autosms",
            "scope": "authentication",
            "realm": "*",
            "action": "autosms",
        }
        if policy:
            new_policy.update(policy)
        self.set_policy(new_policy)

        context["Client"] = client_ip
        context["RequestUser"] = getUserFromParam({"user": user})

        result = get_auth_AutoSMSPolicy()
        assert result == expected_result

    def test_no_client_policy(self):
        """
        autosms enabled with no client and no user. Will do for all clients in a realm
        """
        self.do_autosms_test(
            None, "horst", "1.2.3.4", True,
        )

    def test_allowed_ip(self):
        """
        autosms enabled for a client. Will send autosms for a client in the subnet
        """
        self.do_autosms_test(
            {"client": "172.16.200.0/24"}, "horst", "172.16.200.123", True,
        )

    def test_ip_not_allowed(self):
        """
        autosms enabled for a client. Will not send autosms for a client outside this subnet
        """
        self.do_autosms_test(
            {"client": "172.16.200.0/24"}, "horst", "192.168.20.1", False,
        )

    def test_client_and_user_policy(self):
        """
        autosms enabled for a client and for a user. Will send autosms for this user
        """
        self.do_autosms_test(
            {"client": "172.16.200.0/24", "user": "horst"},
            "horst",
            "172.16.200.10",
            True,
        )

    def test_user_not_allowed(self):
        """
        autosms enabled for a client and for a user. Will not send autosms for another user
        """
        self.do_autosms_test(
            {"client": "172.16.200.0/24", "user": "horst"},
            "localuser",
            "172.16.200.10",
            False,
        )
