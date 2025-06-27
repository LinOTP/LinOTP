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
Test userservice enrollment functionality for the motp token
"""

import base64
import re

from linotp.tests import TestController


class TestMOTPTokenEnrollController(TestController):
    user = "passthru_user1@myDefRealm"
    pw = "geheim1"

    def setUp(self):
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

    # Unfortunately we can't use `@pytest.mark.parametrize` with class-based tests.

    def test_enroll_motp_token_with_otpkey(self):
        self._run_motp_token_enroll_test(otpkey="DEADBEEFDEADBEEF")

    def test_enroll_motp_token_no_otpkey(self):
        self._run_motp_token_enroll_test(otpkey=None)

    def _run_motp_token_enroll_test(self, otpkey=None):
        params = {
            "type": "motp",
            "description": "automated test",
            "otppin": "1111",
        }
        if otpkey is not None:
            params["otpkey"] = otpkey
        self.create_policy(
            {
                "name": "enrollmotp",
                "scope": "selfservice",
                "action": "enrollMOTP",
            }
        )
        response = self.make_userservice_request("enroll", params, (self.user, self.pw))
        # Ensure that seed matches otpkey provided, or at least looks reasonable
        assert "otpkey" in response.json["detail"]
        value = response.json["detail"]["otpkey"].get("value")
        assert value is not None
        assert value.startswith("seed://")
        seed = value[7:]
        if otpkey:
            assert seed == otpkey
        else:
            assert re.match(r"^[0-9A-F]{16}$", seed), (
                "seed must be 16 hexadecimal digits"
            )
        # Ensure that otpauth URL looks cromulent
        assert "enrollment_url" in response.json["detail"]
        assert (
            url := response.json["detail"]["enrollment_url"].get("value")
        ) is not None
        assert url.startswith(
            "otpauth://motp/LinOTP:" + self.user[: self.user.find("@")] + "?"
        )
        # Ensure secret in the otpauth URL corresponds to seed/otpkey
        assert (m := re.search(r"secret=(.*)&", url)) is not None
        assert base64.b32decode(m.group(1) + "=" * 6) == seed.encode("ascii")
