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


"""
  Test linotp.lib.tokens.emailtoken
"""

from mock import patch
import smtplib
import re
import time

from linotp.tests import TestController, url


class TestEmailtokenController(TestController):

    pin = '1234'
    default_email_address = 'paul@example.com'
    patch_smtp = None
    mock_smtp_instance = None
    challenge_validity = 5
    token_serial = 'LSEM12345678'

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        params = {
            'EmailProvider': 'linotp.lib.emailprovider.SMTPEmailProvider',
            'EmailProviderConfig': '{ "SMTP_SERVER": "mail.example.com",\
                               "SMTP_USER": "secret_user",\
                               "SMTP_PASSWORD": "secret_pasword" }',
            'EmailChallengeValidityTime': self.challenge_validity,
            'EmailBlockingTimeout': 0,
        }
        response = self.make_system_request('setConfig', params)
        assert '"status": true' in response

        # Enroll token
        params = {
            'type': 'email',
            'serial': self.token_serial,
            'description': "E-mail token enrolled in functional tests",
            'email_address': self.default_email_address,
        }
        response = self.make_admin_request('init', params)
        assert '"value": true' in response

        params = {
            "serial": self.token_serial,
            "user": "root",
            "pin": self.pin,
            }
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response

        # Patch (replace) smtplib.SMTP class to prevent e-mails from being sent out
        self.patch_smtp = patch('smtplib.SMTP', spec=smtplib.SMTP)
        mock_smtp_class = self.patch_smtp.start()
        self.mock_smtp_instance = mock_smtp_class.return_value
        self.mock_smtp_instance.sendmail.return_value = []

    def tearDown(self):
        self.patch_smtp.stop()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()
        TestController.tearDown(self)

    def test_default(self):
        """
        Test the default case: enroll, assign, send challenge, get successful response
        """
        response, otp = self._trigger_challenge()
        self._assert_email_sent(response)
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root', 'pass': self.pin + otp})
        response_json = response.json
        self.assertTrue(response_json['result']['status'])
        self.assertTrue(response_json['result']['value'])


    def test_multiple_challenges(self):
        """
        Test with multiple challenges

        To do this we extend the challenge validity time and set a small blocking timeout.
        By waiting 5 seconds after every request we make sure a new e-mail is sent (and challenge
        created). In the end we send a response with one of the challenges (not the last one).
        """
        params = {
            'EmailChallengeValidityTime': 120,
            'EmailBlockingTimeout': 3,
        }
        response = self.make_system_request('setConfig', params)
        assert '"status": true' in response

        # trigger 1st challenge
        response, _ = self._trigger_challenge()
        self._assert_email_sent(response)
        time.sleep(5)
        # trigger 2nd challenge
        response, _ = self._trigger_challenge()
        self._assert_email_sent(response)
        time.sleep(5)
        # trigger 3rd challenge and store resulting information
        stored_response, stored_otp = self._trigger_challenge()
        self._assert_email_sent(response)
        time.sleep(5)
        # trigger 4th challenge
        response, _ = self._trigger_challenge()
        self._assert_email_sent(response)

        # Send the response with the stored values from the 3rd challenge
        transaction_id = stored_response['detail']['transactionid']
        # since we are sending the transactionid we only need the otp (without pin)
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root', 'pass': stored_otp, 'transactionid': transaction_id})
        response = response.json
        self.assertTrue(response['result']['status'])
        self.assertTrue(response['result']['value'])

    def test_timeout(self):
        """
        Test that challenges timeout after 'EmailChallengeValidityTime'
        """
        response, otp = self._trigger_challenge()
        self._assert_email_sent(response)
        time.sleep(int(self.challenge_validity * 1.2))  # we wait 120% of the challenge timeout
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root', 'pass': self.pin + otp})
        response = response.json
        self.assertTrue(response['result']['status'])
        self.assertFalse(response['result']['value'], "Challenge should have timed out")

    def test_blocking(self):
        """
        Test that no new e-mails are sent out during EmailBlockingTimeout
        """
        params = {
            'EmailBlockingTimeout': 3,
        }
        response = self.make_system_request('setConfig', params)
        assert '"status": true' in response

        # Trigger 1st challenge (that should send e-mail)
        response, _ = self._trigger_challenge()
        self._assert_email_sent(response)

        # Trigger 2nd challenge (should send no e-mail)
        response, _ = self._trigger_challenge()
        self.assertEqual("e-mail with otp already submitted", response['detail']['message'])

        time.sleep(5)  # wait for blocking timeout to pass

        # Trigger 3rd challenge (that should send e-mail)
        response, otp = self._trigger_challenge()
        self._assert_email_sent(response)

        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root', 'pass': self.pin + otp})
        response_json = response.json
        self.assertTrue(response_json['result']['status'])
        self.assertTrue(response_json['result']['value'])

        time.sleep(5)  # wait again to prevent problems with other tests

    def test_smtplib_exceptions(self):
        """
        Verify that SMTPRecipientsRefused exception is caught and no challenge is created.

        We assume that this works for other smtplib exceptions as well, because from LinOTPs point
        of view they behave in the same way.
        """
        # Get existing challenges (to verify later that no new ones were added)
        response_string = self.make_admin_request('checkstatus', {'user': 'root'})
        response = response_string.json
        values = response['result']['value']['values']
        existing_challenges = values.get(self.token_serial, {}).get('challenges', {})

        # Trigger SMTPRecipientsRefused exception when sendmail is called
        exception_to_raise = smtplib.SMTPRecipientsRefused(
            {
                self.default_email_address: (
                    450,
                    '4.1.8 <test@invalid.subdomain.linotp.de>: ' +
                        'Sender address rejected: Domain not found'
                    )
                }
            )
        self.mock_smtp_instance.sendmail.side_effect = exception_to_raise
        response_string = self.app.get(url(controller='validate', action='check'),
                                       params={'user': 'root', 'pass': self.pin})
        response = response_string.json
        expected_error = "error sending e-mail %r" % exception_to_raise
        self.assertEqual(expected_error, response['detail']['message'], "Error message does not match")

        # Get new challenges
        response_string = self.make_admin_request('checkstatus', {'user': 'root'})
        response = response_string.json
        values = response['result']['value']['values']
        new_challenges = values.get(self.token_serial, {}).get('challenges', {})

        # Verify that no challenge was created (the exception should have prevented it)
        self.assertTrue(existing_challenges == new_challenges,
                        "No new challenges should have been created.")

    def _trigger_challenge(self):
        """
        Triggers a challenge by doing validate/check with only the pin

        :return: tuple of the response and the otp value
        :rtype: (dict, string)
        """
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root', 'pass': self.pin})
        self.assertTrue(self.mock_smtp_instance.sendmail.call_count >= 1,
                        "smtplib.SMTP.sendmail() should have been called at least once")
        call_args = self.mock_smtp_instance.sendmail.call_args
        ordered_args = call_args[0]
        email_from = ordered_args[0]
        email_to = ordered_args[1]
        message = ordered_args[2]
        self.assertEqual("linotp@example.com", email_from)
        self.assertEqual(self.default_email_address, email_to)

        matches = re.search('\d{6}', message)
        self.assertTrue(matches is not None)
        otp = matches.group(0)
        self.assertEqual(6, len(otp))
        return response.json, otp

    def _assert_email_sent(self, response):
        """
        Assert that the response contains information stating that the e-mail with the challenge
        has been sent.

        :param response: The response returned by validate/check
        :response type: dict
        """
        self.assertEqual("e-mail sent successfully", response['detail']['message'])
        self.assertTrue(response['result']['status'])
        self.assertFalse(response['result']['value'])
