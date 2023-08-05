# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

"""
sql resolver tests
"""

import json
import logging

from passlib.hash import atlassian_pbkdf2_sha1
from passlib.hash import bcrypt as passlib_bcrypt
from passlib.hash import phpass as passlib_phpass

from .sql_test_controller import SQLTestController

PASSWORDS = [
    "#,`/^?/#)!'",
    '^.%{[(&}>#].)"#',
    " #$%&@`/:;<=>?[\\]^{|}~“‘+",
    "řƷ&ȧᚽÂᚯŚǡȒᛧƳ¢ȡǗǠȏȄ.ŁœňᛅȤ",
    "ȴĔⱫⱨǝțíǧIė06Ĵᚯ)ƻãĩƜǇǠŚƽĢ",
    "ⱠᛝǾᛥĀ;ǢⱩùΊǎǸŊᛂãȌű¸óȟŗɇ!ĺ",
]

log = logging.getLogger(__name__)


class SQLResolverSpecialPasswordTest(SQLTestController):
    def setUp(self):
        """create an sql user table some users and the sql resolver"""

        SQLTestController.setUp(self)
        self.setUpSQL()

        return

    def tearDown(self):
        """drop the users and the user table"""

        self.dropUsers()
        self.delete_all_token()

        return SQLTestController.tearDown(self)

    def define_otp_pin_policy(self, otppin="password"):
        """
        create the policy to check for password instead of pin
        """

        params = {
            "name": "otppin_poilcy",
            "action": "otppin=" + otppin,
            "scope": "authentication",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response.body

    def run_password_check(self, user, password, realm):
        self.define_otp_pin_policy("pin")

        # ------------------------------------------------------------------ --

        # create token for user

        pin = "mypin!"
        secret = "mein_geheimnis"
        serial = "pw_" + user

        params = {
            "type": "pw",
            "otpkey": secret,
            "user": user,
            "realm": realm,
            "serial": serial,
            "pin": pin,
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response.body, response

        # ------------------------------------------------------------------ --

        # run a wrong login, so that the token failcount increments

        params = {"user": user, "pass": pin + "1" + secret}

        response = self.make_validate_request("check", params=params)
        assert '"value": false' in response

        # ------------------------------------------------------------------ --

        # verify that the token count is incremented to 1

        params = {"serial": serial}

        response = self.make_admin_request("show", params=params)
        jresp = json.loads(response.body)
        token_info = (
            jresp.get("result", {}).get("value", {}).get("data", [{}])[0]
        )
        assert token_info.get("LinOtp.FailCount", -1) == 1

        # ------------------------------------------------------------------ --

        # now login to the selfservice and run the token reset

        # run a wrong login, so that the token failcount increments

        params = {"user": user, "pass": pin + secret}

        response = self.make_validate_request(
            "check", params=params, method="GET"
        )
        assert '"value": true' in response

        # ------------------------------------------------------------------ --

        # create the policy to check for password instead of pin

        self.define_otp_pin_policy("password")

        # ------------------------------------------------------------------ --

        # verify that correct password works

        params = {"user": user, "pass": password + secret}

        response = self.make_validate_request("check", params=params)
        assert '"value": true' in response

        # verify that wrong password works

        params = {"user": user, "pass": password + "1" + secret}

        response = self.make_validate_request("check", params=params)
        assert '"value": false' in response

        return

    def test_sqlresolver_random_passwords(self):
        """
        test that we can use pbkdf2 and bcrypt passwords with an sql resolver
        """

        users = {}

        # ------------------------------------------------------------------ --

        # create the User schema

        self.createUserTable()

        # ------------------------------------------------------------------ --
        # define resolver and realm

        realm = "sqlPassRealm"

        self.addSqlResolver("my_sql_pass_users")
        self.addSqlRealm(realm, "my_sql_pass_users", defaultRealm=True)

        # ------------------------------------------------------------- --

        i = 0

        # add users
        for password in PASSWORDS:
            i += 1
            name = "bach%d" % i
            bach_password = password
            bach_password_hash = passlib_bcrypt.hash(bach_password)

            users[name] = {
                "login": name,
                "uid": "%d" % i,
                "telephonenumber": "",
                "mobile": bach_password,
                "surname": "Bach%d" % i,
                "givenname": "Johann Sebastian",
                "password": bach_password_hash,
                "mail": "j%d.s@bach.de" % i,
            }

            assert passlib_bcrypt.verify(bach_password, bach_password_hash)

            self.addUser(**users[name])

            user = users[name]["login"]
            password = users[name]["mobile"]
            try:
                self.run_password_check(user, password, realm=realm)
            except Exception as exx:
                pass
        return


# eof
