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
"""LinOTP Selenium Test for e-mail token"""

import logging
import re
from subprocess import CalledProcessError, check_output

import integration_data as data
import pytest

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.helper import get_from_tconfig, is_radius_disabled
from linotp_selenium_helper.smtp_server import EmailProviderServer
from linotp_selenium_helper.validate import Validate

logger = logging.getLogger(__name__)


class TestEmailToken:
    @pytest.fixture(autouse=True)
    def setUp(self, testcase: TestCase):
        self.testcase = testcase

        self.data = {
            "realm_name": "SE_emailtoken",
            "username": "hans",
            "email_recipient": "hans@example.local",
            "email_token_pin": "1234",
        }

        self.testcase.reset_resolvers_and_realms(
            data.sepasswd_resolver, self.data["realm_name"]
        )

        self.testcase.manage_ui.token_view.delete_all_tokens()

    def enroll_email_token(self):
        # Enroll e-mail token
        user_view = self.testcase.manage_ui.user_view
        user_view.select_realm(self.data["realm_name"])
        user_view.select_user(self.data["username"])
        description = "Rolled out by Selenium"
        expected_email_address = self.data["email_recipient"]
        email_token = self.testcase.manage_ui.token_enroll.create_email_token(
            pin=self.data["email_token_pin"],
            email_address=expected_email_address,
            description=description,
        )
        return email_token


class TestEmailTokenEnroll(TestEmailToken):
    def test_enroll_token(self):
        """
        Enroll e-mail token.

        After enrolling it verifies that the token info contains the
        correct e-mail.
        """
        expected_email_address = self.data["email_recipient"]
        email_token = self.enroll_email_token()

        token_info = self.testcase.manage_ui.token_view.get_token_info(
            email_token
        )
        description = "Rolled out by Selenium"
        expected_description = expected_email_address + " " + description
        assert (
            expected_email_address
            == token_info["LinOtp.TokenInfo"]["email_address"]
        ), "Wrong e-mail address was set for e-mail token."
        assert (
            expected_description == token_info["LinOtp.TokenDesc"]
        ), "Token description doesn't match"


class TestEmailTokenAuth(TestEmailToken):
    @pytest.fixture(autouse=True)
    def enrolled_email_token(self, setUp):
        self.enroll_email_token()

    @pytest.mark.skipif(is_radius_disabled(), reason="Radius is disabled.")
    def test_radius_auth(self):
        def radius_auth(
            username, realm_name, pin, radius_secret, radius_server, state=None
        ):
            call_array = "python ../../../tools/linotp-auth-radius -f ../../../test.ini".split()
            call_array.extend(
                [
                    "-u",
                    username + "@" + realm_name,
                    "-p",
                    pin,
                    "-s",
                    radius_secret,
                    "-r",
                    radius_server,
                ]
            )
            if state:
                call_array.extend("-t", state)

            logger.debug("Executing %s", " ".join(call_array))
            try:
                return check_output(call_array)
            except CalledProcessError as e:
                assert e.returncode == 0, (
                    "radius auth process exit code %s. Command:%s Ouptut:%s"
                    % (e.returncode, " ".join(e.cmd), e.output)
                )

        radius_server = get_from_tconfig(
            ["radius", "server"],
            default=self.testcase.http_host.split(":")[0],
        )
        radius_secret = get_from_tconfig(["radius", "secret"], required=True)

        with EmailProviderServer(self.testcase, 20) as smtpsvc:
            # Authenticate with RADIUS
            rad1 = radius_auth(
                self.data["username"],
                self.data["realm_name"],
                self.data["email_token_pin"],
                radius_secret,
                radius_server,
            )
            m = re.search(r"State:\['(\d+)'\]", rad1)
            assert m is not None, (
                "'State' not found in linotp-auth-radius output. %r" % rad1
            )
            state = m.group(1)
            logger.debug("State: %s", state)

            otp = smtpsvc.get_otp()

        rad2 = radius_auth(
            self.data["username"],
            self.data["realm_name"],
            otp,
            radius_secret,
            radius_server,
            state,
        )
        assert "Access granted to user " + self.data["username"] in rad2, (
            "Access not granted to user. %r" % rad2
        )

    def test_web_api_auth(self):
        with EmailProviderServer(self.testcase, 20) as smtpsvc:
            # Authenticate over Web API
            validate = Validate(
                self.testcase.http_protocol,
                self.testcase.http_host,
                self.testcase.http_port,
                self.testcase.http_username,
                self.testcase.http_password,
            )
            access_granted, validate_resp = validate.validate(
                user=self.data["username"] + "@" + self.data["realm_name"],
                password=self.data["email_token_pin"],
            )
            assert (
                not access_granted
            ), "Should return false because this request only triggers the challenge."
            try:
                message = validate_resp["detail"]["message"]
            except KeyError as e:
                raise KeyError(
                    e.message
                    + " | detail.message should be present %r" % validate_resp
                )
            assert message == "e-mail sent successfully", (
                "Wrong validate response %r" % validate_resp
            )
            otp = smtpsvc.get_otp()

        access_granted, validate_resp = validate.validate(
            user=self.data["username"] + "@" + self.data["realm_name"],
            password=self.data["email_token_pin"] + otp,
        )
        assert access_granted, "Could not authenticate user %s %r" % (
            self.data["username"],
            validate_resp,
        )
