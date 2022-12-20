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

"""
"""

import json

from linotp.tests import TestController


class TestTokenlist(TestController):
    """
    test the search on a token list
    """

    serials = []

    def setUp(self):
        """setup the Test Controller"""
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """make the dishes"""
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)
        return

    def test_wildcard_search(self):
        """
        test the token search for a user
        """

        login_name = "pass.thru@example.com"
        realm = "mydefrealm"

        # create token
        params = {"type": "spass", "user": "%s@%s" % (login_name, realm)}

        response = self.make_admin_request("init", params=params)
        assert "serial" in response

        jresp = json.loads(response.body)
        serial = jresp.get("detail", {}).get("serial", "")

        # ----------------------------------------------------------------- --

        # first search for the token user with the exact name

        params = {
            "page": 1,
            "query": login_name,
            "qtype": "loginname",
            "sortname": None,
            "sortorder": None,
            "rp": 1,
        }

        response = self.make_manage_request("tokenview_flexi", params=params)
        jresp = json.loads(response.body)
        token_id = (
            jresp.get("result", {})
            .get("value", {})
            .get("rows", [{}])[0]
            .get("id")
        )

        assert serial == token_id, response

        # ----------------------------------------------------------------- --

        # first search for the token user with the exact name with real realm

        params = {
            "page": 1,
            "query": "%s@mydefrealm" % login_name,
            "qtype": "loginname",
            "sortname": None,
            "sortorder": None,
            "rp": 1,
        }

        response = self.make_manage_request("tokenview_flexi", params=params)
        jresp = json.loads(response.body)
        token_id = (
            jresp.get("result", {})
            .get("value", {})
            .get("rows", [{}])[0]
            .get("id")
        )

        assert serial == token_id, response

        # ----------------------------------------------------------------- --

        # search for the token user with the wildcard name

        params = {
            "page": 1,
            "query": "pass.thru@example.*",
            "qtype": "loginname",
            "sortname": None,
            "sortorder": None,
            "rp": 1,
        }

        response = self.make_manage_request("tokenview_flexi", params=params)
        jresp = json.loads(response.body)
        token_id = (
            jresp.get("result", {})
            .get("value", {})
            .get("rows", [{}])[0]
            .get("id")
        )

        assert serial == token_id, response

        # ----------------------------------------------------------------- --

        # search for the token user with the wildcard name

        params = {
            "page": 1,
            "query": "pass.thru*",
            "qtype": "loginname",
            "sortname": None,
            "sortorder": None,
            "rp": 1,
        }

        response = self.make_manage_request("tokenview_flexi", params=params)
        jresp = json.loads(response.body)
        token_id = (
            jresp.get("result", {})
            .get("value", {})
            .get("rows", [{}])[0]
            .get("id")
        )

        assert serial == token_id, response

        return
