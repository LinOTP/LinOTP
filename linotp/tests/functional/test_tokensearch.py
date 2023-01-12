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
"""
import json

from linotp.tests import TestController


class TestTokensearch(TestController):
    """
    test the search on a token list
    """

    serials = []

    def setUp(self):
        """setup the Test Controller"""
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self._cache_splitAtSign()

    def tearDown(self):
        """make the dishes"""
        self.restore_splitAtSign()
        self.remove_tokens()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)
        return

    def remove_tokens(self):
        """
        remove all tokens, which are in the internal array of serial

        :return: - nothing -
        """
        for serial in self.serials:
            param = {"serial": serial}
            response = self.make_admin_request("remove", params=param)
            assert "value" in response
            self.serials.remove(serial)

        return

    def _cache_splitAtSign(self):
        response = self.make_system_request(
            "getConfig", params={"key": "splitAtSign"}
        )

        jresp = json.loads(response.body)
        splitAtSig = (
            jresp.get("result", {})
            .get("value", {})
            .get("getConfig splitAtSig")
        )

        self.splitAtSig = splitAtSig

    def restore_splitAtSign(self):
        try:
            splitAtSig = self.splitAtSig
        except:
            pass
        else:
            if splitAtSig:
                self.set_splitAtSign(splitAtSig)
            else:
                response = self.make_system_request(
                    "delConfig", params={"key": "splitAtSign"}
                )

    def set_splitAtSign(self, value: bool):
        response = self.make_system_request(
            "setConfig", params={"splitAtSign": json.dumps(value)}
        )

        msg = f'"setConfig splitAtSign:{json.dumps(value)}": true'

        assert msg in response

    def create_token(self, params):
        params = {"type": "spass", "user": "pass.thru@example.com"}

        response = self.make_admin_request("init", params=params)
        assert "serial" in response

        jresp = json.loads(response.body)
        serial = jresp.get("detail", {}).get("serial", "")
        if serial:
            self.serials.append(serial)

        return serial

    def test_singel_character_wildcard_search(self):
        """single char wildcard test for user lookup in token view"""

        self.set_splitAtSign(False)

        # create token
        params = {"type": "spass", "user": "pass.thru@example.com"}
        serial = self.create_token(params)

        # search for token which belong to a certain user
        params = {"user": "pass.thru@example.com"}
        response = self.make_admin_request("show", params=params)
        assert serial in response

        # search with wildcard for token which belong to a certain user
        params = {"user": "pass*thru@example.com"}
        response = self.make_admin_request("show", params=params)
        assert serial in response

        return

    def test_search_token_with_params(self):
        self.set_splitAtSign(False)

        # create token
        params = {"type": "spass", "user": "pass.thru@example.com"}
        serial = self.create_token(params)

        search_dicts = [
            {"params": {"userId": "1234"}, "serial_in_response": True},
            {
                "params": {"resolverName": "myDefRes"},
                "serial_in_response": True,
            },
            {
                "params": {"userId": "1234", "resolverName": "myDefRes"},
                "serial_in_response": True,
            },
            {
                "params": {
                    "userId": "NonExistingId",
                    "resolverName": "myDefRes",
                },
                "serial_in_response": False,
            },
            {"params": {"userId": "asd"}, "serial_in_response": False},
            {
                "params": {"resolverName": "mydefres"},
                "serial_in_response": False,
            },
            {
                "params": {"resolverName": "NonExistingResolver"},
                "serial_in_response": False,
            },
        ]

        for search_dict in search_dicts:
            params = search_dict["params"]
            response = self.make_api_v2_request("/tokens/", params=params)
            assert search_dict["serial_in_response"] == (serial in response)


# eof #
