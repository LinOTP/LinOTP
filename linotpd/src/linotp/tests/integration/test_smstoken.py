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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
from subprocess import check_output
import unittest
import re

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.sms_token import SmsToken
from linotp_selenium_helper.helper import get_from_tconfig, is_radius_disabled
from linotp_selenium_helper.validate import Validate
from linotp_selenium_helper.smtp_server import SMSProviderServer

import integration_data as data

"""LinOTP Selenium Test for sms token"""


class TestSmsToken(TestCase):

    def setUp(self):
        TestCase.setUp(self)
        self.realm_name = "SE_smstoken"
        self.reset_resolvers_and_realms(
            data.sepasswd_resolver, self.realm_name)
        self.manage_ui.token_view.delete_all_tokens()

    def test_enroll(self):
        """
        Enroll sms token. After enrolling it verifies that the token info contains the
        correct sms. Then a user is authenticated using challenge response over RADIUS
        and Web API.
        """
        realm_name = self.realm_name

        radius_server = get_from_tconfig(
            ['radius', 'server'],
            default=self.http_host.split(':')[0],
        )
        radius_secret = get_from_tconfig(['radius', 'secret'], required=True)
        disable_radius = get_from_tconfig(
            ['radius', 'disable'], default='False')

        # Enroll sms token
        username = "rollo"
        sms_token_pin = "1234"
        phone_number = "+49(0)1234-24"
        description = "Rolled out by Selenium"

        user_view = self.manage_ui.user_view
        user_view.select_realm(realm_name)
        user_view.select_user(username)

        sms_token = SmsToken(driver=self.driver,
                             base_url=self.base_url,
                             pin=sms_token_pin,
                             phone=phone_number,
                             description=description)

        token_view = self.manage_ui.token_view
        token_info = token_view.get_token_info(sms_token.serial)
        self.assertEqual(phone_number, token_info['LinOtp.TokenInfo']['phone'],
                         "Wrong phone number was set for sms token.")

        # Authenticate with RADIUS
        if disable_radius.lower() == 'true':
            print "Testconfig option radius.disable is set to True. Skipping RADIUS test!"
        else:
            call_array = "linotp-auth-radius -f ../../../test.ini".split()
            call_array.extend(['-u', username + "@" + realm_name,
                               '-p', '1234',
                               '-s', radius_secret,
                               '-r', radius_server])
            with SMSProviderServer(self, 10) as smtpsvc:
                rad1 = check_output(call_array)
                m = re.search(r"State:\['(\d+)'\]", rad1)
                self.assertTrue(m is not None,
                                "'State' not found in linotp-auth-radius output. %r" % rad1)
                state = m.group(1)
                print "State: %s" % state
                otp = smtpsvc.get_otp()

            call_array = "linotp-auth-radius -f ../../../test.ini".split()
            call_array.extend(['-u', username + "@" + realm_name,
                               '-p', otp,
                               '-t', state,
                               '-s', radius_secret,
                               '-r', radius_server])
            rad2 = check_output(call_array)
            self.assertTrue("Access granted to user " + username in rad2,
                            "Access not granted to user. %r" % rad2)

        # Authenticate over Web API
        validate = Validate(self.http_protocol, self.http_host, self.http_port,
                            self.http_username, self.http_password)

        with SMSProviderServer(self, 10) as smtpsvc:
            access_granted, validate_resp = validate.validate(user=username + "@" + realm_name,
                                                              password=sms_token_pin)
            self.assertFalse(access_granted,
                             "Should return false because this request only triggers the challenge.")
            try:
                message = validate_resp['detail']['message']
            except KeyError:
                self.fail("detail.message should be present %r" %
                          validate_resp)
            self.assertEqual(message,
                             "sms submitted",
                             "Wrong validate response %r" % validate_resp)
            otp = smtpsvc.get_otp()

        access_granted, validate_resp = validate.validate(user=username + "@" + realm_name,
                                                          password=sms_token_pin + otp)
        self.assertTrue(access_granted,
                        "Could not authenticate user %s %r" % (username, validate_resp))
