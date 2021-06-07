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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""LinOTP Selenium Test for e-mail token"""

from subprocess import check_output, CalledProcessError
import logging
import re
import pytest

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.helper import get_from_tconfig, is_radius_disabled
from linotp_selenium_helper.validate import Validate
from linotp_selenium_helper.smtp_server import EmailProviderServer

import integration_data as data

logger = logging.getLogger(__name__)


class TestEmailToken(TestCase):

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.realm_name = "SE_emailtoken"
        self.username = "hans"

        self.email_recipient = "hans@example.local"
        self.reset_resolvers_and_realms(
            data.sepasswd_resolver, self.realm_name)

        self.email_token_pin = "1234"

        self.token_view = self.manage_ui.token_view
        self.token_view.delete_all_tokens()

    def enroll_email_token(self):

        # Enroll e-mail token
        user_view = self.manage_ui.user_view
        user_view.select_realm(self.realm_name)
        user_view.select_user(self.username)
        description = "Rolled out by Selenium"
        expected_email_address = self.email_recipient
        email_token = self.manage_ui.token_enroll.create_email_token(
                                 pin=self.email_token_pin,
                                 email_address=expected_email_address,
                                 description=description)
        return email_token


class TestEmailTokenEnroll(TestEmailToken):

    def test_enroll_token(self):
        """
        Enroll e-mail token.

        After enrolling it verifies that the token info contains the
        correct e-mail.
        """
        expected_email_address = self.email_recipient
        email_token = self.enroll_email_token()

        token_info = self.token_view.get_token_info(email_token)
        description = "Rolled out by Selenium"
        expected_description = expected_email_address + " " + description
        assert expected_email_address == token_info['LinOtp.TokenInfo']['email_address'], \
                         "Wrong e-mail address was set for e-mail token."
        assert expected_description == token_info['LinOtp.TokenDesc'], \
                         "Token description doesn't match"


class TestEmailTokenAuth(TestEmailToken):

    @pytest.fixture(autouse=True)
    def enrolled_email_token(self, setUp):
        self.enroll_email_token()

    @pytest.mark.skipif(is_radius_disabled(), reason="Radius is disabled.")
    def test_radius_auth(self):

        def radius_auth(username, realm_name,
                        pin, radius_secret,
                        radius_server, state=None):
            call_array = "python ../../../tools/linotp-auth-radius -f ../../../test.ini".split()
            call_array.extend(['-u', username + "@" + realm_name,
                               '-p', pin,
                               '-s', radius_secret,
                               '-r', radius_server])
            if state:
                call_array.extend('-t', state)

            logger.debug("Executing %s" % ' '.join(call_array))
            try:
                return check_output(call_array)
            except CalledProcessError as e:
                assert e.returncode == 0, \
                    "radius auth process exit code %s. Command:%s Ouptut:%s" % \
                    (e.returncode, ' '.join(e.cmd), e.output)

        radius_server = get_from_tconfig(
            ['radius', 'server'],
            default=self.http_host.split(':')[0],
        )
        radius_secret = get_from_tconfig(['radius', 'secret'], required=True)

        with EmailProviderServer(self, 20) as smtpsvc:
            # Authenticate with RADIUS
            rad1 = radius_auth(
                self.username, self.realm_name,
                self.email_token_pin,
                radius_secret, radius_server)
            m = re.search(r"State:\['(\d+)'\]", rad1)
            assert m is not None, \
                            "'State' not found in linotp-auth-radius output. %r" % rad1
            state = m.group(1)
            logger.debug("State: %s" % state)

            otp = smtpsvc.get_otp()

        rad2 = radius_auth(
            self.username, self.realm_name,
            otp, radius_secret,
            radius_server, state)
        assert "Access granted to user " + self.username in rad2, \
                        "Access not granted to user. %r" % rad2

    def test_web_api_auth(self):

        with EmailProviderServer(self, 20) as smtpsvc:

            # Authenticate over Web API
            validate = Validate(self.http_protocol, self.http_host,
                                self.http_port, self.http_username,
                                self.http_password)
            access_granted, validate_resp = validate.validate(user=self.username + "@" + self.realm_name,
                                                              password=self.email_token_pin)
            assert not access_granted, \
                             "Should return false because this request only triggers the challenge."
            try:
                message = validate_resp['detail']['message']
            except KeyError:
                self.fail("detail.message should be present %r" %
                          validate_resp)
            assert message == \
                             "e-mail sent successfully", \
                             "Wrong validate response %r" % validate_resp
            otp = smtpsvc.get_otp()

        access_granted, validate_resp = validate.validate(user=self.username + "@" + self.realm_name,
                                                          password=self.email_token_pin + otp)
        assert access_granted, \
                        "Could not authenticate user %s %r" % (self.username, validate_resp)
