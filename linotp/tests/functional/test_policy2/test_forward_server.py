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


"""used to do functional testing of the server forwarding"""

import logging
from unittest.mock import patch

import pytest

from linotp.tests import TestController

Rad_Serv = None


class MockForwardServerPolicy:
    @staticmethod
    def do_request(servers, env, user, passw, options):
        global Rad_Serv
        Rad_Serv = servers

        return True, None


class TestForwardServer(TestController):
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)
        global Rad_Serv
        Rad_Serv = None

    # We need to resort to dirty tricks to get access to the `caplog` fixture,
    # because `unittest`-based tests don't support getting at pytest fixtures
    # in the usual way (by listing them as method parameters). This sucks, and
    # the tests should really be rewritten to get rid of the `TestController`
    # class.

    @pytest.fixture(autouse=True)
    def caplog_fixture(self, caplog):  # pylint: disable=redefined-outer-name
        self.caplog = caplog  # pylint: disable=attribute-defined-outside-init

    def define_user_forward(self):
        # ------------------------------------------------------------------ --

        params = {
            "name": "forward_user",
            "realm": "mydefrealm",
            "action": ("forward_server=radius://127.0.0.1:1812/?secret=geheim1"),
            "client": "",
            "user": "passthru_user1",
            "time": "",
            "active": True,
            "scope": "authentication",
        }

        response = self.make_system_request("setPolicy", params=params)

        name = params["name"]
        assert "setPolicy " + name in response, response

    def define_all_forward(self):
        params = {
            "name": "forward",
            "realm": "mydefrealm",
            "action": ("forward_server=radius://192.168.100.180:1812/?secret=geheim1"),
            "client": "",
            "user": "*",
            "time": "",
            "active": True,
            "scope": "authentication",
        }

        response = self.make_system_request("setPolicy", params=params)

        name = params["name"]
        assert "setPolicy " + name in response, response

    @patch("linotp.lib.auth.validate.ForwardServerPolicy", MockForwardServerPolicy)
    def test_server_forwarding(self):
        """
        Checking auth forwarding with check
        """

        # ------------------------------------------------------------------ --

        self.define_all_forward()

        self.define_user_forward()

        # check passthru_user1

        params = {"user": "passthru_user1", "pass": "geheim1"}

        _response = self.make_validate_request(action="check", params=params)

        assert "127.0.0.1" in Rad_Serv, Rad_Serv

        params = {"user": "passthru_user2", "pass": "geheim1"}

        _response = self.make_validate_request(action="check", params=params)

        assert "127.0.0.1" not in Rad_Serv, Rad_Serv

        return

    @patch("linotp.lib.auth.validate.ForwardServerPolicy", MockForwardServerPolicy)
    def test_server_forwarding2(self):
        """
        Checking auth forwarding with check
        """

        # ------------------------------------------------------------------ --

        self.define_user_forward()

        self.define_all_forward()

        # check passthru_user1

        params = {"user": "passthru_user1", "pass": "geheim1"}

        _response = self.make_validate_request(action="check", params=params)

        assert "127.0.0.1" in Rad_Serv, Rad_Serv

        params = {"user": "passthru_user2", "pass": "geheim1"}

        _response = self.make_validate_request(action="check", params=params)

        assert "127.0.0.1" not in Rad_Serv, Rad_Serv

        return

    @patch("linotp.lib.auth.validate.ForwardServerPolicy", MockForwardServerPolicy)
    def test_server_forwarding_with_no_token_0(self):
        """
        conditional forward request only if no user has no token.
        This test shows that the request is NOT forwarded if the user DOES have
        a token.
        """

        # ------------------------------------------------------------------ --

        # define forwarding policies

        params = {
            "name": "forward_user",
            "realm": "mydefrealm",
            "action": (
                "forward_server=radius://127.0.0.1:1812/"
                "?secret=geheim1, forward_on_no_token"
            ),
            "client": "",
            "user": "passthru_user1",
            "time": "",
            "active": True,
            "scope": "authentication",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # create token for user passthru_user1

        params = {
            "type": "pw",
            "otpkey": "test123!",
            "user": "passthru_user1",
            "pin": "pin",
            "serial": "my_pw_token",
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response, response

        # ----------------------------------------------------------------- --

        # check passthru_user1 - should not be forwarded to server

        global Rad_Serv
        Rad_Serv = None

        with self.caplog.at_level(logging.INFO, logger="linotp.lib.auth.validate"):
            self.caplog.clear()
            params = {"user": "passthru_user1", "pass": "pintest123!"}

            response = self.make_validate_request(action="check", params=params)

        assert "false" not in response, response
        assert Rad_Serv is None, Rad_Serv

        nf_msgs = [t for t in self.caplog.record_tuples if "NOT forwarding" in t[2]]
        assert len(nf_msgs) == 1

        # This assertion only makes sense if `action_detail` is not overwritten
        # by later log entries.

        # assert g.audit["action_detail"] == "NOT forwarded"

    @patch("linotp.lib.auth.validate.ForwardServerPolicy", MockForwardServerPolicy)
    def test_server_forwarding_with_no_token_1(self):
        """
        conditional forward request only if no user has no token.
        This test establishes that the request is NOT forwarded if the user
        DOES have a token and it is disabled.
        """

        # ------------------------------------------------------------------ --

        # define forwarding policies

        params = {
            "name": "forward_user",
            "realm": "mydefrealm",
            "action": (
                "forward_server=radius://127.0.0.1:1812/"
                "?secret=geheim1, forward_on_no_token"
            ),
            "client": "",
            "user": "passthru_user1",
            "time": "",
            "active": True,
            "scope": "authentication",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # create token for user passthru_user1

        params = {
            "type": "pw",
            "otpkey": "test123!",
            "user": "passthru_user1",
            "pin": "pin",
            "serial": "my_pw_token",
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response, response

        # ----------------------------------------------------------------- --

        # disable token of passthru_user1

        params = {"serial": "my_pw_token"}
        response = self.make_admin_request("disable", params=params)
        assert "false" not in response, response

        # ----------------------------------------------------------------- --

        # passthru_user1 should now be forwarded

        with self.caplog.at_level(logging.INFO):
            self.caplog.clear()
            params = {"user": "passthru_user1", "pass": "geheim1"}
            response = self.make_validate_request(action="check", params=params)

        assert "false" in response, response
        assert Rad_Serv is None, Rad_Serv

        nf_msgs = [
            t
            for t in self.caplog.record_tuples
            if t[2].startswith("NOT forwarding auth request")
        ]
        assert len(nf_msgs) == 1

        # This assertion only makes sense if `action_detail` is not overwritten
        # by later log entries.

        # assert g.audit["action_detail"] == "NOT forwarded"

    @patch("linotp.lib.auth.validate.ForwardServerPolicy", MockForwardServerPolicy)
    def test_server_forwarding_with_no_token_2(self):
        """
        conditional forward request only if no user has no token.
        This test shows that the request IS forwarded if the user DOESN'T have
        a token.
        """

        # ------------------------------------------------------------------ --

        # define forwarding policies

        params = {
            "name": "forward_user",
            "realm": "mydefrealm",
            "action": (
                "forward_server=radius://127.0.0.1:1812/"
                "?secret=geheim1, forward_on_no_token"
            ),
            "client": "",
            "user": "passthru_user1",
            "time": "",
            "active": True,
            "scope": "authentication",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        # Note that passthru_user1 does not have a token.

        # ----------------------------------------------------------------- --

        # passthru_user1 should now be forwarded

        params = {"user": "passthru_user1", "pass": "geheim1"}

        _response = self.make_validate_request(action="check", params=params)
        assert "127.0.0.1" in Rad_Serv, Rad_Serv

        nf_msgs = [
            t
            for t in self.caplog.record_tuples
            if t[2].startswith("forwarding auth request")
        ]
        assert len(nf_msgs) == 1

        # This assertion only makes sense if `action_detail` is not overwritten
        # by later log entries.

        # assert g.audit["action_detail"] == "Forwarded, result True"


# eof #
