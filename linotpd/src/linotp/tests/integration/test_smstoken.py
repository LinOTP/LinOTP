# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""LinOTP Selenium Test for sms token"""

import time
from subprocess import check_output
import re
import mailbox
from email.utils import parsedate

from linotp_selenium_helper import TestCase, PasswdUserIdResolver, Realm
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.sms_token import SmsToken
from linotp_selenium_helper.set_config import SetConfig
from linotp_selenium_helper.helper import get_from_tconfig
from linotp_selenium_helper.validate import Validate


class TestSmsToken(TestCase):

    def test_enroll(self):
        """
        Enroll sms token. After enrolling it verifies that the token info contains the
        correct sms. Then a user is authenticated using challenge response over RADIUS
        and Web API.
        """

        sms_provider_config = get_from_tconfig(['sms_token', 'sms_provider_config'])
        radius_server = get_from_tconfig(
            ['radius', 'server'],
            default=self.http_host.split(':')[0],
            )
        radius_secret = get_from_tconfig(['radius', 'secret'], required=True)
        disable_radius = get_from_tconfig(['radius', 'disable'], default='False')

        driver = self.driver

        # Create Passwd UserIdResolver
        #
        # Expected content of /etc/se_mypasswd is:
        #
        # hans:x:42:0:Hans Müller,Room 22,+49(0)1234-22,+49(0)5678-22,hans@example.com:x:x
        # susi:x:1336:0:Susanne Bauer,Room 23,+49(0)1234-24,+49(0)5678-23,susanne@example.com:x:x
        # rollo:x:21:0:Rollobert Fischer,Room 24,+49(0)1234-24,+49(0)5678-24,rollo@example.com:x:x
        #
        passwd_name = "SE_myPasswd"
        passwd_id_resolver = PasswdUserIdResolver(passwd_name, driver,
                                                  self.base_url, filename="/etc/se_mypasswd")
        time.sleep(1)

        # Create realm for all resolvers
        resolvers_realm = [passwd_id_resolver]
        realm_name = "SE_smstoken"
        realm = Realm(realm_name, resolvers_realm)
        realm.create(driver, self.base_url)
        time.sleep(1)

        # Set SMTP sms config
        if sms_provider_config:
            parameters = {
                'SMSProvider': 'smsprovider.SmtpSMSProvider.SmtpSMSProvider',
                'SMSProviderConfig': sms_provider_config
            }
            set_config = SetConfig(self.http_protocol, self.http_host, self.http_username,
                                   self.http_password)
            result = set_config.setConfig(parameters)
            self.assertTrue(result, "It was not possible to set the config")
        else:
            print "No sms_provider_config in testconfig file. Using LinOTP default."

        # Enroll sms token
        driver.get(self.base_url + "/manage")
        time.sleep(2)
        user_view = UserView(driver, self.base_url, realm_name)
        username = "rollo"
        user_view.select_user(username)
        sms_token_pin = "1234"
        description = "Rolled out by Selenium"
        sms_token = SmsToken(driver=self.driver,
                             base_url=self.base_url,
                             pin=sms_token_pin,
                             description=description)
        token_view = TokenView(self.driver, self.base_url)
        token_info = token_view.get_token_info(sms_token.serial)
        expected_phone_number = "+49(0)1234-24"
        self.assertEqual(expected_phone_number, token_info['LinOtp.TokenInfo']['phone'],
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
            rad1 = check_output(call_array)
            m = re.search(r"State:\['(\d+)'\]", rad1)
            self.assertTrue(m is not None,
                            "'State' not found in linotp-auth-radius output. %r" % rad1)
            state = m.group(1)
            print "State: %s" % state
            otp = self._get_otp()
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
        validate = Validate(self.http_protocol, self.http_host, self.http_username,
                            self.http_password)
        access_granted, validate_resp = validate.validate(user=username + "@" + realm_name,
                                            password=sms_token_pin)
        self.assertFalse(access_granted,
                         "Should return false because this request only triggers the challenge.")
        try:
            message = validate_resp['detail']['message']
        except KeyError:
            self.fail("detail.message should be present %r" % validate_resp)
        self.assertEqual(message,
                         "sms submitted",
                         "Wrong validate response %r" % validate_resp)
        otp = self._get_otp()
        access_granted, validate_resp = validate.validate(user=username + "@" + realm_name,
                                            password=sms_token_pin + otp)
        self.assertTrue(access_granted,
                        "Could not authenticate user %s %r" % (username, validate_resp))

    def _get_otp(self):
        """Internal method to get the OTP, either interactively over the commandline or
        by checking a mailbox (mbox).
        """
        interactive = get_from_tconfig(['sms_token', 'interactive'], required=True)
        mbox_filepath = get_from_tconfig(['sms_token', 'mbox_filepath'],
                                         default="/var/mail/jenkins")
        otp = None
        if interactive.lower() == 'true':
            otp = raw_input("OTP (check your e-mail): ")
        else:
            time.sleep(10) # Wait for sms to arrive
            mybox = mailbox.mbox(mbox_filepath)
            mybox.lock()
            try:
                print "Mailbox length: " + str(len(mybox))
                def get_mail_delivery_date(key_mail_pair):
                    mail = key_mail_pair[1]
                    date_tuple = parsedate(mail['Delivery-date'])
                    return time.mktime(date_tuple)
                newest_mail_key, newest_mail = max(mybox.iteritems(), key=get_mail_delivery_date)
                self.assertTrue(newest_mail is not None, "No sms in mbox")
                payload = newest_mail.get_payload()
                matches = re.search(r"\d{6}", payload)
                self.assertTrue(matches is not None, "No OTP in sms message %r" % newest_mail)
                otp = matches.group(0)
                mybox.remove(newest_mail_key)
            except Exception as exc:
                raise exc
            finally:
                mybox.close()
                mybox.unlock()
        return otp

