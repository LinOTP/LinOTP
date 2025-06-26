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

""" """

from urllib.parse import urlparse

from linotp.tests import TestController


class TestTokenlabel(TestController):
    def setUp(self):
        self.create_common_resolvers()
        self.create_common_realms()
        self.delete_all_policies()

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_policies()
        return TestController.tearDown(self)

    def test_token_label(self):
        """test setting the token label"""
        # enroll a token max1
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "serial": "hmac1",
            "type": "hmac",
            "genkey": 1,
        }
        response = self.make_admin_request(action="init", params=params)

        jresp = response.json
        enrollment_url = jresp["detail"]["enrollment_url"]["value"]
        # test for deprecated googleurl
        googleurl = jresp["detail"]["googleurl"]["value"]
        assert googleurl == enrollment_url, response

        uri = urlparse(enrollment_url)
        token_label = uri.path.partition(":")[2]

        assert token_label == "max1", response
        assert uri.hostname == "hotp"

        params = {
            "name": "tokenlabel",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "*",
            "action": "tokenlabel=<s>:<u>@<r>",
            "client": "",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        jresp = response.json
        assert jresp["result"]["value"]["setPolicy tokenlabel"], response

        # enroll a token max1
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "serial": "hmac1",
            "type": "hmac",
            "genkey": 1,
        }
        response = self.make_admin_request(action="init", params=params)

        jresp = response.json
        enrollment_url = jresp["detail"]["enrollment_url"]["value"]
        # test for deprecated googleurl
        googleurl = jresp["detail"]["googleurl"]["value"]
        assert googleurl == enrollment_url, response

        uri = urlparse(enrollment_url)
        token_label = uri.path.partition(":")[2]

        assert token_label == "hmac1%3Amax1%40myOtherRealm", response
        assert uri.hostname == "hotp"

    def test_token_issuer(self):
        """test setting the token issuer"""

        # enroll token for max2 without token issuer
        params = {
            "user": "max2",
            "realm": "myOtherRealm",
            "serial": "hmac2",
            "type": "totp",
            "genkey": 1,
        }

        response = self.make_admin_request(action="init", params=params)
        jresp = response.json
        enrollment_url = jresp["detail"]["enrollment_url"]["value"]
        # test for deprecated googleurl
        googleurl = jresp["detail"]["googleurl"]["value"]
        assert googleurl == enrollment_url, response

        uri = urlparse(enrollment_url)
        issuer = uri.path.partition(":")[0]

        assert issuer == "/LinOTP", response
        assert uri.hostname == "totp"

        params = {
            "name": "tokenissuer",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "*",
            "action": 'tokenissuer="it\'s me"',
            "client": "",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        jresp = response.json
        assert jresp["result"]["value"]["setPolicy tokenissuer"], response

        # enroll token for max2
        params = {
            "user": "max2",
            "realm": "myOtherRealm",
            "serial": "hmac2",
            "type": "totp",
            "genkey": 1,
        }

        response = self.make_admin_request(action="init", params=params)
        jresp = response.json
        enrollment_url = jresp["detail"]["enrollment_url"]["value"]
        # test for deprecated googleurl
        googleurl = jresp["detail"]["googleurl"]["value"]
        assert googleurl == enrollment_url, response

        uri = urlparse(enrollment_url)
        issuer = uri.path.partition(":")[0]

        assert issuer == "/it%27s%20me", response
        assert uri.hostname == "totp"
