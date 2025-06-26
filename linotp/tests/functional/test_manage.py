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


""" """

import json
import logging
import os

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestManageController(TestController):
    def setUp(self):
        """
        resolver: reso1 (my-passwd), reso2 (my-pass2)
        realm: realm1, realm2
        token: token1 (r1), token2 (r1), token3 (r2)
        """

        TestController.setUp(self)

        # remove all other tokens
        self.delete_all_token()

        # create resolvers
        params = {
            "name": "reso1",
            "type": "passwdresolver",
            "fileName": os.path.join(self.fixture_path, "my-passwd"),
        }
        response = self.make_system_request("setResolver", params=params)

        assert '"value": true' in response, response

        params = {
            "name": "reso2",
            "type": "passwdresolver",
            "fileName": os.path.join(self.fixture_path, "my-pass2"),
        }
        response = self.make_system_request("setResolver", params=params)
        assert '"value": true' in response, response

        # create realms
        params = {
            "realm": "realm1",
            "resolvers": "useridresolver.PasswdIdResolver.IdResolver.reso1",
        }
        response = self.make_system_request("setRealm", params=params)
        assert '"value": true' in response, response

        params = {
            "realm": "realm2",
            "resolvers": "useridresolver.PasswdIdResolver.IdResolver.reso2",
        }
        response = self.make_system_request("setRealm", params=params)
        assert '"value": true' in response, response

        # create token
        params = {
            "serial": "token1",
            "type": "pw",
            "pin": "otppin",
            "otpkey": "secret",
            "user": "heinz",
            "realm": "realm1",
        }
        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, response

        params = {
            "serial": "token2",
            "type": "pw",
            "pin": "otppin",
            "otpkey": "secret",
            "user": "nick",
            "realm": "realm1",
        }
        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, response

        params = {
            "serial": "token3",
            "type": "pw",
            "pin": "otppin",
            "otpkey": "secret",
            "user": "renate",
            "realm": "realm2",
        }
        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, response

    def tearDown(self):
        """
        make the dishes
        """
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        return TestController.tearDown(self)

    ###########################################################################
    def test_index(self):
        """
        Manage: testing index access
        """
        response = self.make_manage_request("", params={})
        assert "<title>Management - LinOTP</title>" in response, response

    def test_policies(self):
        """
        Manage: testing policies tab
        """
        response = self.make_manage_request("policies", params={})

        assert 'id="policy_export"' in response, response
        assert 'id="policy_import"' in response, response
        assert 'id="button_policy_delete"' in response, response

    def test_audit(self):
        """
        Manage: testing audit trail
        """
        response = self.make_manage_request("audittrail", params={})

        assert 'table id="audit_table"' in response, response
        assert "view_audit();" in response, response

    def test_tokenview(self):
        """
        Manage: testing tokenview
        """
        response = self.make_manage_request("tokenview", params={})

        assert "button_losttoken" in response, response
        assert "button_tokeninfo" in response, response
        assert "button_resync" in response, response
        assert "button_tokenrealm" in response, response
        assert 'table id="token_table"' in response, response
        assert "view_token();" in response, response
        assert "tokenbuttons();" in response, response

    def test_userview(self):
        """
        Manage: testing userview
        """
        response = self.make_manage_request("userview", params={})

        assert 'table id="user_table"' in response, response
        assert "view_user();" in response, response

    def test_tokenflexi(self):
        """
        Manage: testing the tokenview_flexi method
        """
        response = self.make_manage_request("tokenview_flexi", params={})
        assert '"total": 3' in response, response

        # analyse the reply for token info
        resp = json.loads(response.body)
        tokens = resp.get("result", {}).get("value", {}).get("rows", [])

        match_count = 0
        for token in tokens:
            if token.get("id") == "token1":
                assert "heinz" in token["cell"], resp
                match_count += 1
            elif token.get("id") == "token2":
                assert "nick" in token["cell"], resp
                match_count += 1
            elif token.get("id") == "token3":
                assert "renate" in token["cell"], resp
                match_count += 1
        assert match_count == 3, f"Not all matches found in resp {resp!r}"

        # only renates token
        params = {"qtype": "loginname", "query": "renate"}
        response = self.make_manage_request("tokenview_flexi", params=params)
        testbody = response.body.replace("\n", " ").replace("\r", "").replace("  ", " ")
        assert '"total": 1' in testbody, testbody

        # analyse the reply for token info
        resp = json.loads(response.body)
        tokens = resp.get("result", {}).get("value", {}).get("rows", [])

        match_count = 0
        for token in tokens:
            if token.get("id") == "token3":
                assert "renate" in token["cell"], resp
                match_count += 1
        assert match_count == 1, f"Not all matches found in resp {resp!r}"

        # only tokens in realm1
        params = {"qtype": "realm", "query": "realm1"}
        response = self.make_manage_request("tokenview_flexi", params=params)
        assert '"total": 2' in response, response

        # analyse the reply for token info
        resp = json.loads(response.body)
        tokens = resp.get("result", {}).get("value", {}).get("rows", [])

        match_count = 0
        for token in tokens:
            if token.get("id") == "token1":
                assert "heinz" in token["cell"], resp
                match_count += 1
            elif token.get("id") == "token2":
                assert "nick" in token["cell"], resp
                match_count += 1

        assert match_count == 2, f"Not all matches found in resp {resp!r}"

        # search in all columns
        params = {"qtype": "all", "query": "token2"}
        response = self.make_manage_request("tokenview_flexi", params=params)
        assert '"total": 1' in response, response

        # analyse the reply for token info
        resp = json.loads(response.body)
        tokens = resp.get("result", {}).get("value", {}).get("rows", [])

        match_count = 0
        for token in tokens:
            if token.get("id") == "token2":
                assert "nick" in token["cell"], resp
                match_count += 1

        assert match_count == 1, f"Not all matches found in resp {resp!r}"

    def test_userflexi(self):
        """
        Manage: testing the userview_flexi method
        """
        # No realm, no user
        response = self.make_manage_request("userview_flexi", params={})

        assert '"total": 0' in response, response

        # No realm, no user

        params = {
            "page": 1,
            "rp": 15,
            "sortname": "username",
            "sortorder": "asc",
            "query": "",
            "qtype": "username",
            "realm": "realm1",
        }

        response = self.make_manage_request("userview_flexi", params=params)
        assert '"id": "heinz"' in response, response

        params = {
            "page": 1,
            "rp": 15,
            "sortname": "username",
            "sortorder": "desc",
            "query": "",
            "qtype": "username",
            "realm": "realm2",
        }
        response = self.make_manage_request("userview_flexi", params=params)
        assert '"id": "renate"' in response, response

    def test_tokeninfo(self):
        """
        Manage: Testing tokeninfo dialog
        """

        response = self.make_manage_request("tokeninfo", params={"serial": "token1"})

        msg = "class=tokeninfoOuterTable>LinOtp.TokenSerialnumber"

        assert msg in response, response
        assert "Heinz Hirtz" in response, response
        assert "token1" in response, response
