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
test the administrative handling of providers:
  * create new provider
  * check for default provider
  * define default provider
  * usage of provider via policy
  * fallback to default if policy does not match
"""

from mock import patch
import logging
import json

import smsprovider.FileSMSProvider

from linotp.tests import TestController

log = logging.getLogger(__name__)


# mocking hook is starting here
SMS_MESSAGE_OTP = ('', '')
SMS_MESSAGE_CONFIG = {}


def mocked_submitMessage(FileSMS_Object, *argparams, **kwparams):

    # this hook is defined to grep the otp and make it globaly available
    global SMS_MESSAGE_OTP
    SMS_MESSAGE_OTP = argparams

    # we call here the original sms submitter - as we are a functional test
    global SMS_MESSAGE_CONFIG
    SMS_MESSAGE_CONFIG = FileSMS_Object.config

    return True


class TestProviderController(TestController):

    def setUp(self):

        super(TestProviderController, self).setUp()
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):

        self.removeProviderConfig()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_policies()

        super(TestProviderController, self).tearDown()

    def create_sms_token(self, serial=None, token_params=None):

        params = {'otpkey': ('1234567890123456789012345678901234567890'
                             '123456789012345678901234'),
                  'realm': 'myDefRealm',
                  'type': 'sms',
                  'user': 'user1',
                  'pin': '1234',
                  'phone': '016012345678',
                  'selftest_admin': 'superadmin'
                  }

        if token_params:
            params.update(token_params)
        if serial:
            params['serial'] = serial

        response = self.make_admin_request(action='init', params=params)

        return response

    def setPolicy(self, policy_params=None):

        params = {'name': 'smsprovider_newone',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'sms_provider=newone',
                  'user': '*',
                  }
        if policy_params:
            params.update(policy_params)

        response = self.make_system_request(action='setPolicy',
                                            params=params)

        return response

    def define_legacy_provider(self, provider_params=None):
        """
        define the legacy provider via setConfig
        """
        params = {'SMSProviderTimeout': '301',
                  'SMSProviderConfig': '{"file":"/tmp/legacy"}',
                  'SMSProvider': 'smsprovider.FileSMSProvider.FileSMSProvider',
                  'SMSProviderConfig.type': 'password'}

        if provider_params:
            params.update(provider_params)

        response = self.make_system_request('setConfig', params=params)

        return response

    def removeProviderConfig(self):
        entries = ["linotp.Provider.Default.sms_provider",
                   'linotp.SMSProvider',
                   "linotp.SMSProviderConfig",
                   "linotp.SMSProvider.newone",
                   "linotp.SMSProvider.newone.Config",
                   "linotp.SMSProvider.newone.Timeout"
                   ]

        for entry in entries:
            params = {'key': entry}
            _response = self.make_system_request('delConfig', params=params)
        return

    def define_new_provider(self, provider_params=None):
        """
        define the new provider via setProvider
        """
        params = {'name': 'newone',
                  'config': '{"file":"/tmp/newone"}',
                  'timeout': '301',
                  'type': 'sms',
                  'class': 'smsprovider.FileSMSProvider.FileSMSProvider'
                  }

        if provider_params:
            params.update(provider_params)

        response = self.make_system_request('setProvider', params=params)

        return response

    def test_create_legacy_provider(self):
        """
        check if legacy provider is default after create
        """
        response = self.define_legacy_provider()
        self.assertTrue('/tmp/legacy' in response, response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('imported_default', {})
        self.assertTrue(provider.get('Default', False), response)

        params = {'type': 'email'}
        response = self.make_system_request('getProvider', params=params)
        self.assertTrue('"value": {}' in response, response)

        return

    def test_create_new_provider(self):
        """
        check if new provider is default after create
        """
        response = self.define_new_provider()
        self.assertTrue('"value": true' in response, response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('newone', {})
        self.assertTrue(provider.get('Default', False), response)

        response = self.define_legacy_provider()
        self.assertTrue('/tmp/legacy' in response, response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('imported_default', {})
        self.assertFalse(provider.get('Default', False), response)

        return

    @patch.object(smsprovider.FileSMSProvider.FileSMSProvider,
                  'submitMessage', mocked_submitMessage)
    def test_legacy_default_provider(self):
        """
        check if legacy provider is loaded by default
        """

        response = self.define_legacy_provider()
        self.assertTrue('/tmp/legacy' in response, response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('imported_default', {})
        self.assertTrue(provider.get('Default', False), response)

        serial = 'sms1234'
        response = self.create_sms_token(serial=serial)
        self.assertTrue(serial in response)

        params = {'serial': serial, 'pass': '1234'}
        response = self.make_validate_request('check_s', params=params)

        global SMS_MESSAGE_CONFIG
        self.assertTrue('/tmp/legacy' in SMS_MESSAGE_CONFIG.get('file'))

        return

    @patch.object(smsprovider.FileSMSProvider.FileSMSProvider,
                  'submitMessage', mocked_submitMessage)
    def test_new_provider(self):
        """
        check if legacy provider is loaded by default
        """

        response = self.define_new_provider()
        self.assertTrue('"value": true' in response, response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('newone', {})
        self.assertTrue(provider.get('Default', False), response)

        serial = 'sms1234'
        response = self.create_sms_token(serial=serial)
        self.assertTrue(serial in response)

        params = {'serial': serial, 'pass': '1234'}
        response = self.make_validate_request('check_s', params=params)

        global SMS_MESSAGE_CONFIG
        self.assertTrue('/tmp/newone' in SMS_MESSAGE_CONFIG.get('file'))

        return

    @patch.object(smsprovider.FileSMSProvider.FileSMSProvider,
                  'submitMessage', mocked_submitMessage)
    def test_provider_via_policy(self):
        """
        check if new provider is loaded by policy
        """

        # create legacy provider
        response = self.define_legacy_provider()
        self.assertTrue('/tmp/legacy' in response, response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('imported_default', {})
        self.assertTrue(provider.get('Default', False), response)

        # create new provider
        response = self.define_new_provider()
        self.assertTrue('"value": true' in response, response)

        # check that this is not the default one
        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)
        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('newone', {})
        self.assertFalse(provider.get('Default', True), response)

        # define smsprovider policy to use the 'newone'
        response = self.setPolicy()
        self.assertTrue('"setPolicy smsprovider_newone"' in response,
                        response)

        # trigger sms and check that the correct provider is used
        serial = 'sms1234'
        response = self.create_sms_token(serial=serial)
        self.assertTrue(serial in response)

        params = {'serial': serial, 'pass': '1234'}
        response = self.make_validate_request('check_s', params=params)

        global SMS_MESSAGE_CONFIG
        self.assertTrue('/tmp/newone' in SMS_MESSAGE_CONFIG.get('file'))

        return

    @patch.object(smsprovider.FileSMSProvider.FileSMSProvider,
                  'submitMessage', mocked_submitMessage)
    def test_default_provider_via_policy(self):
        """
        check if default provider is loaded if policy does not match
        """

        # create new provider
        response = self.define_new_provider()
        self.assertTrue('"value": true' in response, response)

        # check that this is the default one
        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)
        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('newone', {})
        self.assertTrue(provider.get('Default', False), response)

        # create legacy provider
        response = self.define_legacy_provider()
        self.assertTrue('/tmp/legacy' in response, response)

        # check that legacy provider is not the default one
        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('imported_default', {})
        self.assertFalse(provider.get('Default', True), response)

        # set legacy provider as default provider
        params = {'type': 'sms', 'name': 'imported_default'}
        response = self.make_system_request('setDefaultProvider',
                                            params=params)
        self.assertTrue('"value": true' in response)

        params = {'type': 'sms'}
        response = self.make_system_request('getProvider', params=params)
        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get('imported_default', {})
        self.assertTrue(provider.get('Default', False), response)

        # define sms provider policy to use the 'newone'
        response = self.setPolicy(policy_params={'user': 'egon', })
        self.assertTrue('"setPolicy smsprovider_newone"' in response,
                        response)

        # trigger sms and check that the default provider is used
        serial = 'sms1234'
        response = self.create_sms_token(serial=serial)
        self.assertTrue(serial in response)

        params = {'serial': serial, 'pass': '1234'}
        response = self.make_validate_request('check_s', params=params)

        global SMS_MESSAGE_CONFIG
        self.assertTrue('/tmp/legacy' in SMS_MESSAGE_CONFIG.get('file'))

        return

# eof #####################################################################
