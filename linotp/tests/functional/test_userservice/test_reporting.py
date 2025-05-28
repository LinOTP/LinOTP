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


"""
Test reporting in userservice controller
"""

from linotp.lib.user import User
from linotp.model.reporting import Reporting
from linotp.tests import TestController
from linotp.tests.functional.test_reporting import DBSession


class TestUserserviceReporting(TestController):
    """
    Test the token reporting triggered via the userservice.
    """

    def setUp(self):
        super().setUp()
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.create_common_resolvers()
        self.create_common_realms()

    def init_token(self, params: dict):
        """Creates the token

        Args:
            params (dict): parameters to init the token with

        Returns:
            str: token serial
        """
        response = self.make_admin_request("init", params=params)
        response_json = response.json
        assert response_json["result"]["value"], response_json
        serial = response_json["detail"]["serial"]
        return serial

    def createSPASS(self, serial="LSSP0001", pin="1test@pin!42"):
        parameters = {"serial": serial, "type": "spass", "pin": pin}
        return self.init_token(parameters)

    def create_reporting_policy(self, policy_params: dict = None):
        policy_params = policy_params or {}
        params = {
            "name": policy_params.get("name", "reporting_policy"),
            "scope": policy_params.get("scope", "reporting"),
            "action": policy_params.get(
                "action",
                "token_total, token_status=active, token_status=inactive, token_status=assigned, token_status=unassigned",
            ),
            "user": policy_params.get("user", "*"),
            "realm": policy_params.get("realm", "*"),
        }
        self.create_policy(params)

    def test_bug_LINOTP_2084_unauthorized_request_does_not_trigger_reporting_userservice_controller(
        self,
    ):
        # create token without triggering reporting
        serial = self.createSPASS()
        # create policy
        self.create_reporting_policy()

        # trigger action that would trigger reporting pre LINOTP-2084
        for action in [
            "assign",
            "unassign",
            "enable",
            "disable",
            "enroll",
            "delete",
            "finishocra2token",
        ]:
            response = self.client.post(
                f"/userservice/{action}", data={"serial": serial}
            )

            # verify no reporting was triggered
            with DBSession() as session:
                entries = session.query(Reporting).all()
                assert [] == entries, action

    def test_authorized_request_does_trigger_reporting_userservice_controller(
        self,
    ):
        actions_to_test = ["enable", "disable"]
        # create token without triggering reporting
        user = "passthru_user1"
        realm = "myDefRealm"
        auth_user = {"login": f"{user}@{realm}", "password": "geheim1"}
        parameters = {
            "serial": "F722362",
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "user": user,
            "pin": "pin",
            "description": "TestToken1",
        }
        serial = self.init_token(parameters)

        # create reporting policy
        self.create_reporting_policy()
        # create selfservice policy
        params = {
            "name": "allow",
            "scope": "selfservice",
            "action": ",".join(actions_to_test),
            "user": "*",
            "realm": "*",
            "active": True,
        }
        response = self.make_system_request("setPolicy", params)

        # trigger action
        for action in actions_to_test:
            response = self.make_userselfservice_request(
                action, params={"serial": serial}, auth_user=auth_user
            )

            # verify no reporting was triggered
            with DBSession() as session:
                entries = session.query(Reporting).all()
                assert 5 == len(entries), action

                # Clean up reporting and Tokens
                session.query(Reporting).delete()
                session.commit()

    def test_authorized_request_does_not_trigger_reporting_userservice_controller_without_policy(
        self,
    ):
        actions_to_test = ["enable", "disable"]
        # create token without triggering reporting
        user = "passthru_user1"
        realm = "myDefRealm"
        auth_user = {"login": f"{user}@{realm}", "password": "geheim1"}
        parameters = {
            "serial": "F722362",
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "user": user,
            "pin": "pin",
            "description": "TestToken1",
        }
        serial = self.init_token(parameters)

        # create policy
        self.create_reporting_policy()

        # trigger action that would trigger reporting pre LINOTP-2084
        for action in actions_to_test:
            response = self.make_userselfservice_request(
                action, params={"serial": serial}, auth_user=auth_user
            )

            # verify no reporting was triggered
            with DBSession() as session:
                entries = session.query(Reporting).all()
                assert [] == entries, action
