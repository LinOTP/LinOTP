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


"""
"""
import os
import logging
from linotp.tests import TestController


log = logging.getLogger(__name__)


class TestSystemController(TestController):

    # ########################################################################
    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()

    def test_setDefault(self):
        '''
        Testing setting default values
        '''

        params = {
            "DefaultMaxFailCount": "21",
            "DefaultSyncWindow": "200",
            "DefaultCountWindow": "20",
            "DefaultOtpLen": "8",
            "DefaultResetFailCount": "False"
        }
        response = self.make_system_request(action='setDefault',
                                            params=params)
        # log.debug("response %s\n",response)
        self.assertTrue('"set DefaultSyncWindow": true' in response, response)
        self.assertTrue('"set DefaultMaxFailCount": true' in response,
                        response)
        self.assertTrue('"set DefaultResetFailCount": true' in response,
                        response)
        self.assertTrue('"set DefaultSyncWindow": true' in response, response)
        self.assertTrue('"set DefaultMaxFailCount": true' in response,
                        response)
        self.assertTrue('"set DefaultCountWindow": true'in response, response)

        params = {"DefaultMaxFailCount": "10",
                  "DefaultSyncWindow": "1000",
                  "DefaultCountWindow": "10",
                  "DefaultOtpLen": "6",
                  "DefaultResetFailCount": "True"
                  }

        response = self.make_system_request(action='setDefault',
                                            params=params)
        # log.info("response %s\n",response)

        self.assertTrue('"set DefaultSyncWindow": true' in response, response)
        self.assertTrue('"set DefaultMaxFailCount": true' in response,
                        response)
        self.assertTrue('"set DefaultResetFailCount": true' in response,
                        response)
        self.assertTrue('"set DefaultSyncWindow": true' in response, response)
        self.assertTrue('"set DefaultMaxFailCount": true' in response,
                        response)
        self.assertTrue('"set DefaultCountWindow": true'in response, response)

    def test_001_resolvers(self):
        """
        setup: delete realms
        """
        self.delete_all_realms()

        params = {"username": "root"}
        response = self.make_admin_request(action='userlist', params=params)

        pass
        params = {"username": "root",
                  "realm": "myMixRealm"}

        response = self.make_admin_request(action='userlist', params=params)

        pass

    def test_001_realms(self):
        """
        """
        self.create_common_resolvers()
        self.create_common_realms()
        response = self.make_system_request(action='getRealms')

        # set realms
        self.assertTrue('"realmname": "mydefrealm"'in response, response)
        self.assertTrue('"realmname": "myotherrealm"'in response, response)
        self.assertTrue('"realmname": "mymixrealm"'in response, response)

        # now check for the different users in the different realms
        params = {"username": "root",
                  "realm": "*"}

        response = self.make_admin_request(action='userlist', params=params)

        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myOtherRes"'in response, response)
        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myDefRes"'in response, response)

        # now check for the different users in the different realms
        params = {"username": "root",
                  "realm": "myDefRealm"
                  }

        response = self.make_admin_request(action='userlist',
                                           params=params)
        # log.info("response %s\n",response)

        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myDefRes"'in response, response)
        self.assertTrue('"root-def-passwd"'in response, response)

        # now check for the different users in the different realms
        params = {"username": "root",
                  "realm": "myMixRealm"}

        response = self.make_admin_request(action='userlist',
                                           params=params)

        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myOtherRes"'in response, response)
        self.assertTrue('"root-myDom-passwd"'in response, response)

        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myDefRes"'in response, response)
        self.assertTrue('"root-def-passwd"'in response, response)

        # now check for the different users in the different realms
        params = {"username": "root"}  # check in default

        response = self.make_admin_request(action='userlist',
                                           params=params)

        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myDefRes"'in response, response)
        self.assertTrue('"root-def-passwd"'in response, response)

        # now set default to myDomain
        params = {"realm": "myOtherRealm"}

        response = self.make_system_request(action='setDefaultRealm',
                                            params=params)
        self.assertTrue('"value": true'in response, response)

        # now check for the different users in the different realms
        params = {"username": "root"}  # check in default

        response = self.make_admin_request(action='userlist',
                                           params=params)

        self.assertTrue('"useridresolver.PasswdIdResolver.'
                        'IdResolver.myOtherRes"'in response, response)
        self.assertTrue('"root-myDom-passwd"'in response, response)

        # now delete the default realm
        params = {"realm": "myOtherRealm"}  # check in default

        response = self.make_system_request(action='delRealm',
                                            params=params)

        self.assertTrue('"delRealm": {'in response, response)
        self.assertTrue('"result": true'in response, response)

        params = {"realms": "*"}

        response = self.make_system_request(action='getRealms',
                                            params=params)
        # set realms
        self.assertTrue('"realmname": "mydefrealm"'in response, response)
        self.assertTrue('"realmname": "myotherrealm"' not in response,
                        response)
        self.assertTrue('"realmname": "mymixrealm"'in response, response)

        # now check for the different users in the different realms
        params = {"username": "def"}  # check in default

        response = self.make_admin_request(action='userlist', params=params)

        self.assertTrue('"value": []'in response, response)

        # now check for the different users in the different realms
        params = {"username": "def",  # check in default
                  "realm": "myDefRealm"
                  }

        response = self.make_admin_request(action='userlist', params=params)
        # log.info("response %s\n",response)
        self.assertTrue('"description": "def User,,,,"'in response, response)

        # now set default to myDomain
        params = {"realm": "myDefRealm"}

        response = self.make_system_request(action='setDefaultRealm',
                                            params=params)
        self.assertTrue('"value": true'in response, response)

        # now check for the different users in the different realms
        params = {"username": "def"}  # check in default

        response = self.make_admin_request(action='userlist', params=params)

        self.assertTrue('"description": "def User,,,,"'in response, response)

        # now set default to myDomain
        params = {"realm": "myMixRealm"}

        response = self.make_system_request(action='setDefaultRealm',
                                            params=params)
        self.assertTrue('"value": true'in response, response)

        # now check for the different users in the different realms
        params = {"username": "root"}  # check in default

        response = self.make_admin_request(action='userlist', params=params)

        self.assertTrue('"root-def-passwd"'in response, response)
        self.assertTrue('"root-myDom-passwd"'in response, response)

        # now set default to myDomain
        params = {"realm": "myOtherRealm"}

        response = self.make_system_request(action='setDefaultRealm',
                                            params=params)
        self.assertTrue('"value": false'in response, response)

        # now check for the different users in the different realms
        params = {"username": "def",  # check in default
                  "resConf": "myDefRes"
                  }

        response = self.make_admin_request(action='userlist',
                                           params=params)
        # log.info("response %s\n",response)
        self.assertTrue('"description": "def User,,,,"'in response, response)
        self.delete_all_realms()
        self.delete_all_resolvers()

    def test_set_default(self):
        '''
        System-controller: set default without matching keys
        '''
        params = {'wrongKey': 'wrongVal'}
        response = self.make_system_request(action='setDefault',
                                            params=params)

        self.assertTrue('"status": false' in response, response)
        self.assertTrue('Usage: setDefault: parameters are' in response,
                        response)

    def test_setconfig_backwards(self):
        '''
        testing setconfig backward compat
        '''
        params = {'key': 'test',
                  'value': 'old',
                  'description': 'old value'}
        response = self.make_system_request(action='setConfig', params=params)

        self.assertTrue('"setConfig test": true' in response, response)

        params = {'key': 'some.resolver.config',
                  'value': 'resolverText',
                  'description': 'resolver test'}
        response = self.make_system_request(action='setConfig', params=params)

        self.assertTrue('"setConfig some.resolver.config": true' in response,
                        response)

    def test_setconfig_typing(self):
        '''
        Test: system/setConfig with typing
        '''
        params = {'secretkey': 'test123',
                  'secretkey.type': 'password'}
        response = self.make_system_request(action='setConfig', params=params)
        log.info(response)
        self.assertTrue('"setConfig secretkey:test123": true' in response,
                        response)

        # the value will be returned transparently
        response = self.make_system_request(action='getConfig',
                                            params={'key': 'secretkey'})
        self.assertTrue("test123" not in response, response)

        # the value will be returned transparently
        params = {'key': 'enclinotp.secretkey'}
        response = self.make_system_request(action='getConfig',
                                            params=params)
        self.assertTrue("test123" not in response, response)

        response = self.make_system_request(action='delConfig',
                                            params={'key': 'secretkey'})
        return

    def test_delResolver(self):
        '''
        Testing the deleting of a resolver
        '''

        params = {'name': 'reso1',
                  'type': 'passwdresolver',
                  'fileName': os.path.join(self.fixture_path, 'my-pass2')}

        response = self.make_system_request(action='setResolver',
                                            params=params)

        self.assertTrue('"value": true' in response, response)

        params = {'name': 'reso2',
                  'type': 'passwdresolver',
                  'fileName': os.path.join(self.fixture_path, 'my-pass2')}

        response = self.make_system_request(action='setResolver',
                                            params=params)

        self.assertTrue('"value": true' in response, response)
        params = {'name': 'reso3',
                  'type': 'passwdresolver',
                  'fileName': os.path.join(self.fixture_path, 'my-pass2')}

        response = self.make_system_request(action='setResolver',
                                            params=params)

        self.assertTrue('"value": true' in response, response)

        response = self.make_system_request(action='getResolvers', params={})

        self.assertTrue('"entry": "linotp.passwdresolver.fileName.reso2"' in
                        response, response)
        self.assertTrue('"entry": "linotp.passwdresolver.fileName.reso1"' in
                        response, response)
        self.assertTrue('"entry": "linotp.passwdresolver.fileName.reso3"' in
                        response, response)

        # create a realm
        params = {'realm': 'realm1',
                  'resolvers': 'passwdresolver.reso1, passwdresolver.reso2'
                  }
        response = self.make_system_request(action='setRealm', params=params)

        self.assertTrue('"value": true' in response, response)

        # try to delete a resolver, that is in a realm
        response = self.make_system_request(action='delResolver',
                                            params={'resolver': 'reso1'})

        self.assertTrue('Resolver u\'reso1\'  still in use' in response,
                        response)

        response = self.make_system_request(action='delResolver',
                                            params={'resolver': 'reso3'})
        self.assertTrue('"value": true' in response, response)

    def test_policy_wrong_name(self):
        '''
        testing to set a policy with a wrong name
        '''
        params = {'name': 'ads ads asd',
                  'action': '*',
                  'scope': 'admin',
                  'realm': '*'}
        response = self.make_system_request(action='setPolicy', params=params)

        self.assertTrue('The name of the policy may only contain'
                        ' the characters'in response, response)

        self.delete_all_policies()

        return

    def test_bad_policy_name_import(self):

        policy_content = '''[ded-ee]
realm = *
active = True
client = ""
user = *
time = ""
action = "otppin=password "
scope = authentication
'''

        upload_files = [("file", "savedPolicy.txt", policy_content)]

        response = self.make_system_request(action='importPolicy',
                                            params={},
                                            upload_files=upload_files)

        self.assertTrue('<status>False</status>' in response, response)
        self.assertTrue('may only contain the characters'in response, response)

        # Now check the policies, that we imported...
        response = self.make_system_request(action='getPolicy', method='POST',
                                            params={}, auth_user='superuser')

        self.assertFalse('ded-ee' in response, response)

        return

    def test_import_policy(self):

        policy_content = '''[resovler_ss1]
realm = realm2
client = None
user = lse_ad:
time = None
action = "webprovisionGOOGLE, "
scope = selfservice
[resovler_ss2]
realm = realm2
client = None
user = "local:, koelbel"
time = None
action = "webprovisionGOOGLEtime, assign, "
scope = selfservice
[ss1_maria]
realm = realm1
client = None
user = maria
time = None
action = "max_count_hotp=10, webprovisionGOOGLE, getotp, webprovisionOCRA, enrollYUBICO, "
scope = selfservice
[SMS]
realm = realm1
client = ""
user = ""
time = ""
action = smstext=The OTP value for <serial>: <otp>
scope = authentication
[ss1_raff]
realm = realm1
client = None
user = None
time = None
action = "webprovisionGOOGLE, max_count_hotp=5, getotp, assign, webprovisionOCRA, webprovisionOCRA, enrollSMS, enrollMOTP, setMOTPPIN, history"
scope = selfservice
[ocra]
realm = *
client = *
user = admin
time = None
action = "request, activationcode, status, "
scope = ocra
[ss1_ocra]
realm = realm1
client = None
user = None
time = None
action = "qrtanurl=https://localhost, "
scope = authentication
[gettoken]
realm = *
client = ""
user = *
time = ""
action = max_count_hotp=50
scope = gettoken
'''

        upload_files = [("file", "savedPolicy.txt", policy_content)]

        response = self.make_system_request(action='importPolicy',
                                            params={},
                                            upload_files=upload_files)

        self.assertTrue('<status>True</status>' in response, response)
        self.assertTrue('<value>8</value>' in response, response)

        # Now check the policies, that we imported...
        response = self.make_system_request(action='getPolicy', method='POST',
                                            params={}, auth_user='superuser')

        self.assertTrue('"resovler_ss1": {' in response, response)
        self.assertTrue('"resovler_ss2": {' in response, response)
        self.assertTrue('"ss1_maria": {' in response, response)
        self.assertTrue('"SMS": {' in response, response)
        self.assertTrue('"ss1_raff": {' in response, response)
        self.assertTrue('"ocra": {' in response, response)
        self.assertTrue('"ss1_ocra": {' in response, response)
        self.assertTrue('"gettoken": {' in response, response)

        # Now we try to upload with access policies.
        params = {'name': 'superuser',
                  'scope': 'system',
                  'action': 'read,write',
                  'realm': '*',
                  'user': 'superuser'}

        response = self.make_system_request(action='setPolicy', method='POST',
                                            params=params,
                                            auth_user='superuser')

        self.assertTrue('"setPolicy superuser":' in response, response)

        params = {'name': 'readsystem',
                  'scope': 'system',
                  'action': 'read',
                  'realm': '*',
                  'user': 'readadmin'}
        response = self.make_system_request(action='setPolicy', method='POST',
                                            params=params,
                                            auth_user='superuser')

        self.assertTrue('"setPolicy readsystem":' in response, response)

        # superuser is allowed to import
        upload_files = [("file", "savedPolicy.txt", policy_content)]
        response = self.make_system_request(action='importPolicy',
                                            method='POST',
                                            params={},
                                            upload_files=upload_files,
                                            auth_user='superuser')

        self.assertTrue('<status>True</status>' in response, response)
        self.assertTrue('<value>8</value>' in response, response)

        # readadmin is not allowed to import
        upload_files = [("file", "savedPolicy.txt", policy_content)]
        response = self.make_system_request(action='importPolicy',
                                            method='POST',
                                            params={},
                                            upload_files=upload_files,
                                            auth_user='readadmin')

        self.assertTrue('Policy check failed. You are not allowed to'
                        ' write system config' in response, response)

        # finally remove all policies
        names = []
        for line in policy_content.split():
            if line[0] == '[':
                name = line.replace('[', '').replace(']', '')
                names.append(name)
        for name in names:
            self.delete_policy(name, auth_user='superuser')

        self.delete_policy('readsystem', auth_user='superuser')
        self.delete_policy('superuser', auth_user='superuser')

        return

# eof ########################################################################
