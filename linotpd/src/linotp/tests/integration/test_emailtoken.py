# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

import time
from subprocess import check_output, CalledProcessError
import re
import mailbox
import unittest
from email.utils import parsedate

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.email_token import EmailToken
from linotp_selenium_helper.set_config import SetConfig
from linotp_selenium_helper.helper import get_from_tconfig, is_radius_disabled
from linotp_selenium_helper.validate import Validate

import integration_data as data

class TestEmailToken(TestCase):

    def setUp(self):
        TestCase.setUp(self)
        self.realm_name = "SE_emailtoken"
        self.username = "hans"

        self.reset_resolvers_and_realms(data.sepasswd_resolver, self.realm_name)

        self.set_email_config()

        self.token_view = TokenView(self)
        self.token_view.delete_all_tokens()

    def set_email_config(self):
        self.email_provider_config = get_from_tconfig(['email_token', 'email_provider_config'])
        self.email_recipient = get_from_tconfig(['email_token', 'recipient'])

        if not self.email_recipient:
            raise unittest.SkipTest("Email recipient not configured")

        self.email_token_pin = "1234"

        # Set SMTP e-mail config
        if self.email_provider_config:
            parameters = {
                'EmailProviderConfig': self.email_provider_config
            }
            set_config = SetConfig(self.http_protocol, self.http_host, self.http_port,
                                   self.http_username, self.http_password)
            result = set_config.setConfig(parameters)
            self.assertTrue(result, "It was not possible to set the config")
        else:
            print "No email_provider_config in testconfig file. Using LinOTP default."

    def enroll_email_token(self):

        # Enroll e-mail token
        self.driver.get(self.base_url + "/manage")
        time.sleep(2)
        user_view = UserView(self.driver, self.base_url, self.realm_name)
        user_view.select_user(self.username)
        description = "Rolled out by Selenium"
        expected_email_address = self.email_recipient
        email_token = EmailToken(driver=self.driver,
                                 base_url=self.base_url,
                                 pin=self.email_token_pin,
                                 email=expected_email_address,
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

        token_info = self.token_view.get_token_info(email_token.serial)
        description = "Rolled out by Selenium"
        expected_description = expected_email_address + " " + description
        self.assertEqual(expected_email_address, token_info['LinOtp.TokenInfo']['email_address'],
                         "Wrong e-mail address was set for e-mail token.")
        self.assertEqual(expected_description, token_info['LinOtp.TokenDesc'],
                         "Token description doesn't match")

class TestEmailTokenAuth(TestEmailToken):
    def setUp(self):
        TestEmailToken.setUp(self)
        self.enroll_email_token()

    @unittest.skipIf(is_radius_disabled(), True)
    def test_radius_auth(self):
        def radius_auth(username, realm_name, pin, radius_secret, radius_server, state=None):
            call_array = "python ../../../tools/linotp-auth-radius -f ../../../test.ini".split()
            call_array.extend(['-u', username + "@" + realm_name,
                               '-p', pin,
                               '-s', radius_secret,
                               '-r', radius_server])
            if state:
                call_array.extend('-t', state)

            print "Executing %s" % ' '.join(call_array)
            try:
                return check_output(call_array)
            except CalledProcessError, e:
                assert e.returncode == 0, \
                    "radius auth process exit code %s. Command:%s Ouptut:%s" % \
                        (e.returncode, ' '.join(e.cmd), e.output)


        radius_server = get_from_tconfig(
            ['radius', 'server'],
            default=self.http_host.split(':')[0],
            )
        radius_secret = get_from_tconfig(['radius', 'secret'], required=True)

        # Authenticate with RADIUS
        rad1 = radius_auth(self.username, self.realm_name, self.email_token_pin, radius_secret, radius_server)
        m = re.search(r"State:\['(\d+)'\]", rad1)
        self.assertTrue(m is not None,
                        "'State' not found in linotp-auth-radius output. %r" % rad1)
        state = m.group(1)
        print "State: %s" % state

        otp = self._get_otp()

        rad2 = radius_auth(self.username, self.realm_name, otp, radius_secret, radius_server, state)
        self.assertTrue("Access granted to user " + self.username in rad2,
                        "Access not granted to user. %r" % rad2)

    def test_web_api_auth(self):

        # Authenticate over Web API
        validate = Validate(self.http_protocol, self.http_host, self.http_port, self.http_username,
                            self.http_password)
        access_granted, validate_resp = validate.validate(user=self.username + "@" + self.realm_name,
                                                           password=self.email_token_pin)
        self.assertFalse(access_granted,
                         "Should return false because this request only triggers the challenge.")
        try:
            message = validate_resp['detail']['message']
        except KeyError:
            self.fail("detail.message should be present %r" % validate_resp)
        self.assertEqual(message,
                         "e-mail sent successfully",
                         "Wrong validate response %r" % validate_resp)
        otp = self._get_otp()
        access_granted, validate_resp = validate.validate(user=self.username + "@" + self.realm_name,
                                                           password=self.email_token_pin + otp)
        self.assertTrue(access_granted,
                        "Could not authenticate user %s %r" % (self.username, validate_resp))

    def _get_otp(self):
        """Internal method to get the OTP, either interactively over the commandline or
        by checking a mailbox (mbox).
        """
        interactive = get_from_tconfig(['email_token', 'interactive'], required=True)
        mbox_filepath = get_from_tconfig(['email_token', 'mbox_filepath'],
                                         default="/var/mail/jenkins")
        otp = None

        def get_mail_delivery_date(key_mail_pair):
            mail = key_mail_pair[1]
            date_tuple = parsedate(mail['Date'])
            return time.mktime(date_tuple)
        def check_mail():
            mybox = mailbox.mbox(mbox_filepath)
            mybox.lock()
            try:
                mbox_len = len(mybox)
                print "Mailbox length: %s" % (mbox_len)
                self.assertGreater(len(mybox), 0, "Email box must contain at least one message")
                newest_mail_key, newest_mail = max(mybox.iteritems(), key=get_mail_delivery_date)
                self.assertTrue(newest_mail is not None, "No e-mail in mbox")
                payload = newest_mail.get_payload()
                matches = re.search(r"\d{6}", payload)
                self.assertTrue(matches is not None, "No OTP in e-mail message %r" % newest_mail)
                otp = matches.group(0)
                mybox.remove(newest_mail_key)
            finally:
                mybox.close()
                mybox.unlock()
            return otp

        if interactive.lower() == 'true':
            otp = raw_input("OTP (check your e-mail): ")
        else:
            wait_count = 10
            while wait_count:
                time.sleep(1)  # Wait for e-mail to arrive
                try:
                    otp = check_mail()
                except AssertionError, mailbox.ExternalClashError:
                    if wait_count == 0:
                        raise
                wait_count -= 1

        return otp
