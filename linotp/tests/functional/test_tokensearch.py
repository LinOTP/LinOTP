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
            self.make_admin_request("remove", params=param)

        response = self.make_api_v2_request("/tokens/")
        token_list = response.json["result"]["value"]["pageRecords"]
        assert token_list == []

    def _cache_splitAtSign(self):
        response = self.make_system_request("getConfig", params={"key": "splitAtSign"})

        jresp = json.loads(response.body)
        splitAtSig = (
            jresp.get("result", {}).get("value", {}).get("getConfig splitAtSig")
        )

        self.splitAtSig = splitAtSig

    def restore_splitAtSign(self):
        try:
            splitAtSig = self.splitAtSig
        except Exception:
            pass
        else:
            if splitAtSig:
                self.set_splitAtSign(splitAtSig)
            else:
                _response = self.make_system_request(
                    "delConfig", params={"key": "splitAtSign"}
                )

    def set_splitAtSign(self, value: bool):
        response = self.make_system_request(
            "setConfig", params={"splitAtSign": json.dumps(value)}
        )

        msg = f'"setConfig splitAtSign:{json.dumps(value)}": true'

        assert msg in response

    def create_token(self, params=None):
        if not params:
            params = {"type": "spass", "user": "pass.thru@example.com"}

        response = self.make_admin_request("init", params=params)
        serial = response.json["detail"]["serial"]
        self.serials.append(serial)

        return serial

    def test_single_character_wildcard_search(self):
        """single char wildcard test for user lookup in token view"""

        self.set_splitAtSign(False)

        # create token
        serial = self.create_token()

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
        serial = self.create_token()

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

    def test_search_token_with_searchTerm(self):
        self.set_splitAtSign(False)
        # create token
        serial = self.create_token()

        search_dicts = [
            {
                "params": {"searchTerm": "/:active:/"},
                "serial_in_response": True,
            },
            {"params": {"searchTerm": serial}, "serial_in_response": True},
            {
                "params": {"searchTerm": "/:inactive:/"},
                "serial_in_response": False,
            },
            {
                "params": {"searchTerm": "SomeOtherSearchTerm"},
                "serial_in_response": False,
            },
        ]
        for search_dict in search_dicts:
            params = search_dict["params"]
            response = self.make_api_v2_request("/tokens/", params=params)
            assert search_dict["serial_in_response"] == (serial in response)

    def test_search_token_with_sorting(self):
        self.set_splitAtSign(False)
        # create n tokens
        n = 5
        for i in range(n):
            token_creation_params = {
                "type": "spass",
                "user": "pass.thru@example.com",
                "description": n - i,
            }
            self.create_token(token_creation_params)

        for sort_key, expected_ids in [
            ("id", [1, 2, 3, 4, 5]),
            ("description", [5, 4, 3, 2, 1]),
        ]:
            # test asc (by default)
            params = {"sortBy": sort_key}
            response = self.make_api_v2_request("/tokens/", params=params)
            records = response.json["result"]["value"]["pageRecords"]
            ids = [token["id"] for token in records]
            assert expected_ids == ids

            # test desc
            params["sortOrder"] = "desc"
            response = self.make_api_v2_request("/tokens/", params=params)
            records = response.json["result"]["value"]["pageRecords"]
            ids = [token["id"] for token in records]
            assert expected_ids[::-1] == ids

    def test_search_token_with_unsupported_sorting_parameter(self):
        self.set_splitAtSign(False)
        self.create_token()

        params = {"sortBy": "CreationDate"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["status"] is False
        assert result["error"]

    def test_search_token_with_no_realm(self):
        self.set_splitAtSign(False)
        serial1 = self.create_token()
        serial2 = self.create_token()

        # remove realm for serial1
        params = {"serial": serial1, "realms": ""}
        response = self.make_admin_request("tokenrealm", params=params)

        params = {"realm": "''"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]

        assert result["value"]["totalRecords"] == 1
        assert serial2 not in response
        serials = [token["serial"] for token in result["value"]["pageRecords"]]
        assert serials == [serial1]


# eof #
