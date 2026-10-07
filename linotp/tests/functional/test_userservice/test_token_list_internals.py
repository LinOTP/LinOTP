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

"""What the selfservice token list may and may not contain."""

from linotp.tests import TestController

AUTH_USER = {"login": "passthru_user1@myDefRealm", "password": "geheim1"}


class TestSelfserviceTokenListInternals(TestController):
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        for policy in [
            {
                "name": "fido2_enroll",
                "action": "enrollFIDO2",
                "user": "*",
                "realm": "*",
                "scope": "selfservice",
            },
            {
                "name": "fido2_rpid",
                "action": "fido2_rp_id=localhost",
                "user": "*",
                "realm": "*",
                "scope": "enrollment",
            },
        ]:
            assert "false" not in self.make_system_request("setPolicy", params=policy)

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def _token_info(self, serial):
        response = self.make_userselfservice_request(
            "usertokenlist", params={}, auth_user=AUTH_USER
        )
        assert response.json["result"]["status"] is True, response
        tokens = {
            entry["LinOtp.TokenSerialnumber"]: entry
            for entry in response.json["result"]["value"]
        }
        assert serial in tokens, response.json
        return tokens[serial]["LinOtp.TokenInfo"]

    def test_the_credential_is_not_in_the_token_list(self):
        """The credential is of no use to the owner and must stay on the server."""
        serial, *_ = self.enroll_fido2_token(auth_user=AUTH_USER)

        token_info = self._token_info(serial)

        assert "fido2_credential" not in token_info, token_info
        assert "registration_challenge" not in token_info, token_info

    def test_the_remaining_token_info_is_still_reported(self):
        """Only the blobs are dropped, the rest of the token info stays."""
        serial, *_ = self.enroll_fido2_token(auth_user=AUTH_USER)

        token_info = self._token_info(serial)

        assert token_info["rp_id"] == "localhost"
        assert token_info["phase"] == "authentication"

    def test_other_token_types_are_unaffected(self):
        response = self.make_admin_request(
            "init",
            params={
                "serial": "HMACPRIV1",
                "type": "hmac",
                "genkey": "1",
                "user": "passthru_user1",
                "realm": "myDefRealm",
                "hashlib": "sha256",
            },
        )
        assert '"value": true' in response, response

        assert self._token_info("HMACPRIV1")["hashlib"] == "sha256"
