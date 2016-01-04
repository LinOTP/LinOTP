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
"""


import os
import logging
from linotp.tests import TestController, url


log = logging.getLogger(__name__)

class TestSystemController(TestController):


    ###############################################################################
    def setUp(self):
        TestController.setUp(self)
        self.set_config_selftest()

    def test_setDefault(self):
        '''
        Testing setting default values
        '''

        """
            response = self.app.get(url_for(controller='page', action='view', id=1))
            get(url, params=None, headers=None, extra_environ=None, status=None, expect_errors=False)

        setDefault: parameters are\
            DefaultMaxFailCount\
            DefaultSyncWindow\
            DefaultCountWindow\
            DefaultOtpLen\
            DefaultResetFailCount\
        "


        """


        parameters = {
                      "DefaultMaxFailCount":"21",
                      "DefaultSyncWindow":"200",
                      "DefaultCountWindow" : "20",
                      "DefaultOtpLen" : "8",
                      "DefaultResetFailCount" : "False"
                      }
        response = self.app.get(url(controller='system', action='setDefault'), params=parameters)
        #log.debug("response %s\n",response)
        assert '"set DefaultSyncWindow": true' in response
        assert '"set DefaultMaxFailCount": true' in response
        assert '"set DefaultResetFailCount": true' in response
        assert '"set DefaultSyncWindow": true' in response
        assert '"set DefaultMaxFailCount": true' in response
        assert '"set DefaultCountWindow": true'in response



        parameters = {
                      "DefaultMaxFailCount":"10",
                      "DefaultSyncWindow":"1000",
                      "DefaultCountWindow" : "10",
                      "DefaultOtpLen" : "6",
                      "DefaultResetFailCount" : "True"
                      }

        response = self.app.get(url(controller='system', action='setDefault'), params=parameters)
        #log.info("response %s\n",response)
        assert '"set DefaultSyncWindow": true' in response
        assert '"set DefaultMaxFailCount": true' in response
        assert '"set DefaultResetFailCount": true' in response
        assert '"set DefaultSyncWindow": true' in response
        assert '"set DefaultMaxFailCount": true' in response
        assert '"set DefaultCountWindow": true'in response

    def test_001_resolvers(self):
        self.delete_all_realms()
        parameters = {
                              "username":"root",
                     }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        parameters = {
                      "username":"root",
                      "realm":"myMixRealm"
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        log.debug(response)


    def test_001_realms(self):
        self.create_common_resolvers()
        self.create_common_realms()
        response = self.app.get(url(controller='system', action='getRealms'))
        #log.info("response %s\n",response)

        ## set realms
        assert '"realmname": "mydefrealm"'in response
        assert '"realmname": "myotherrealm"'in response
        assert '"realmname": "mymixrealm"'in response

        ## now check for the different users in the different realms
        parameters = {
                      "username":"root",
                      "realm":"*"
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)

        ## http://127.0.0.1:5001/admin/userlist?username=root
        ## # description: "root-def-passwd"


        assert '"useridresolver.PasswdIdResolver.IdResolver.myOtherRes"'in response
        assert '"useridresolver.PasswdIdResolver.IdResolver.myDefRes"'in response

        ## now check for the different users in the different realms
        parameters = {
                      "username":"root",
                      "realm":"myDefRealm"
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)

        print response
        assert '"useridresolver.PasswdIdResolver.IdResolver.myDefRes"'in response
        assert '"root-def-passwd"'in response

        ## now check for the different users in the different realms
        parameters = {
                      "username":"root",
                      "realm":"myMixRealm"
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)

        assert '"useridresolver.PasswdIdResolver.IdResolver.myOtherRes"'in response
        assert '"root-myDom-passwd"'in response

        assert '"useridresolver.PasswdIdResolver.IdResolver.myDefRes"'in response
        assert '"root-def-passwd"'in response


        ## now check for the different users in the different realms
        parameters = {
                      "username":"root",  ## check in default
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)

        assert '"useridresolver.PasswdIdResolver.IdResolver.myDefRes"'in response
        assert '"root-def-passwd"'in response


        ## now set default to myDomain
        parameters = {
                      "realm":"myOtherRealm"
                      }

        response = self.app.get(url(controller='system', action='setDefaultRealm'), params=parameters)
        assert '"value": true'in response



        ## now check for the different users in the different realms
        parameters = {
                      "username":"root",  ## check in default
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)
        assert '"useridresolver.PasswdIdResolver.IdResolver.myOtherRes"'in response
        assert '"root-myDom-passwd"'in response


        ## now delete the default realm
        parameters = {
                      "realm":"myOtherRealm",  ## check in default
                      }

        response = self.app.get(url(controller='system', action='delRealm'), params=parameters)
        #log.info("delRealm: %s ------\n%s" % (str(parameters), str(response)))
        assert '"delRealm": {'in response
        assert '"result": true'in response

        parameters = {
                      "realms":"*",
                      }

        response = self.app.get(url(controller='system', action='getRealms'))
        ## set realms
        assert '"realmname": "mydefrealm"'in response
        assert '"realmname": "myotherrealm"' not in response
        assert '"realmname": "mymixrealm"'in response


        ## now check for the different users in the different realms
        parameters = {
                      "username":"def",  ## check in default
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)
        assert '"value": []'in response

        ## now check for the different users in the different realms
        parameters = {
                      "username":"def",  ## check in default
                      "realm":"myDefRealm"
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)
        assert '"description": "def User,,,,"'in response


        ## now set default to myDomain
        parameters = {
                      "realm":"myDefRealm"
                      }

        response = self.app.get(url(controller='system', action='setDefaultRealm'), params=parameters)
        assert '"value": true'in response


        ## now check for the different users in the different realms
        parameters = {
                      "username":"def",  ## check in default
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)
        assert '"description": "def User,,,,"'in response

        ## now set default to myDomain
        parameters = {
                      "realm":"myMixRealm"
                      }

        response = self.app.get(url(controller='system', action='setDefaultRealm'), params=parameters)
        assert '"value": true'in response


        ## now check for the different users in the different realms
        parameters = {
                      "username":"root",  ## check in default
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)
        assert '"root-def-passwd"'in response
        assert '"root-myDom-passwd"'in response



        ## now set default to myDomain
        parameters = {
                      "realm":"myOtherRealm"
                      }

        response = self.app.get(url(controller='system', action='setDefaultRealm'), params=parameters)
        assert '"value": false'in response




        ## now check for the different users in the different realms
        parameters = {
                      "username":"def",  ## check in default
                      "resConf":"myDefRes"
                      }

        response = self.app.get(url(controller='admin', action='userlist'), params=parameters)
        #log.info("response %s\n",response)
        assert '"description": "def User,,,,"'in response
        self.delete_all_realms()
        self.delete_all_resolvers()



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
        response = self.app.post(url(controller='system', action='importPolicy'),
                                 params={},
                                 upload_files=[("file", "savedPolicy.txt", policy_content)])
        print response
        assert '<status>True</status>' in response
        assert '<value>8</value>' in response

        # Now check the policies, that we imported...

        response = self.app.post(url(controller='system', action='getPolicy'),
                                 params={'selftest_admin' : 'superuser'})
        print response
        assert '"resovler_ss1": {' in response
        assert '"resovler_ss2": {' in response
        assert '"ss1_maria": {' in response
        assert '"SMS": {' in response
        assert '"ss1_raff": {' in response
        assert '"ocra": {' in response
        assert '"ss1_ocra": {' in response
        assert '"gettoken": {' in response

        # Now we try to upload with access policies.

        response = self.app.post(url(controller='system', action='setPolicy'),
                                 params={'selftest_admin' : 'superuser',
                                         'name' : 'superuser',
                                         'scope' : 'system',
                                         'action' : 'read,write',
                                         'realm' : '*',
                                         'user' : 'superuser'})
        print response
        assert '"setPolicy superuser":' in response

        response = self.app.post(url(controller='system', action='setPolicy'),
                                 params={'selftest_admin' : 'superuser',
                                         'name' : 'readsystem',
                                         'scope' : 'system',
                                         'action' : 'read',
                                         'realm' : '*',
                                         'user' : 'readadmin'})
        print response
        assert '"setPolicy readsystem":' in response

        # superuser is allowed to import

        response = self.app.post(url(controller='system', action='importPolicy'),
                                 params={'selftest_admin': 'superuser'},
                                 upload_files=[("file", "savedPolicy.txt", policy_content)])
        print response
        assert '<status>True</status>' in response
        assert '<value>8</value>' in response

        # readadmin is not allowed to import

        response = self.app.post(url(controller='system', action='importPolicy'),
                                 params={'selftest_admin': 'readadmin'},
                                 upload_files=[("file", "savedPolicy.txt", policy_content)])
        print response
        assert 'Policy check failed. You are not allowed to write system config' in response

    def test_set_default(self):
        '''
        System-controller: set default without matching keys
        '''
        response = self.app.get(url(controller='system', action='setDefault'),
                                params={'wrongKey': 'wrongVal' })
        print "test_set_default:", response
        assert '"status": false' in response
        assert 'Usage: setDefault: parameters are' in response

    def test_setconfig_backwards(self):
        '''
        testing setconfig backward compat
        '''
        response = self.app.get(url(controller='system', action='setConfig'),
                                params={'key': 'test',
                                        'value': 'old',
                                        'description':'old value'})
        print response
        assert '"setConfig test": true' in response

        response = self.app.get(url(controller='system', action='setConfig'),
                                params={'key': 'some.resolver.config',
                                        'value': 'resolverText',
                                        'description':'resolver test'})
        print response
        assert '"setConfig some.resolver.config": true' in response

    def test_0000_setconfig_typing(self):
        '''
        Test: system/setConfig with typing
        '''
        response = self.app.get(url(controller='system', action='setConfig'),
                                params={'secretkey': 'test123',
                                        'secretkey.type': 'password'})
        log.info(response)
        assert '"setConfig secretkey:test123": true' in response

        ## the value will be returned transparently
        response = self.app.get(url(controller='system', action='getConfig'),
                                params={'key': 'secretkey'})
        assert "test123" not in response

        ## the value will be returned transparently
        response = self.app.get(url(controller='system', action='getConfig'),
                                params={'key': 'enclinotp.secretkey'})
        assert "test123" in response

        response = self.app.get(url(controller='system', action='delConfig'),
                                params={'key':'secretkey'})
        log.info(response)

        return

    def test_delResolver(self):
        '''
        Testing the deleting of a resolver
        '''
        fixture_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'fixtures',
            )
        response = self.app.get(url(controller='system', action='setResolver'),
                                params={'name':'reso1',
                                        'type': 'passwdresolver',
                                        'fileName': os.path.join(fixture_path, 'my-pass2')})
        print response
        assert '"value": true' in response

        response = self.app.get(url(controller='system', action='setResolver'),
                                params={'name':'reso2',
                                        'type': 'passwdresolver',
                                        'fileName': os.path.join(fixture_path, 'my-pass2')})
        print response
        assert '"value": true' in response

        response = self.app.get(url(controller='system', action='setResolver'),
                                params={'name':'reso3',
                                        'type': 'passwdresolver',
                                        'fileName': os.path.join(fixture_path, 'my-pass2')})
        print response
        assert '"value": true' in response

        response = self.app.get(url(controller='system', action='getResolvers'),
                                params={})
        print response
        assert '"entry": "linotp.passwdresolver.fileName.reso2"' in response
        assert '"entry": "linotp.passwdresolver.fileName.reso1"' in response
        assert '"entry": "linotp.passwdresolver.fileName.reso3"' in response

        # create a realm

        response = self.app.get(url(controller='system', action='setRealm'),
                                params={'realm': 'realm1',
                                        'resolvers': 'linotp.passwdresolver.fileName.reso1, linotp.passwdresolver.fileName.reso2'})
        print response
        assert '"value": true' in response

        # try to delete a resolver, that is in a realm
        response = self.app.get(url(controller='system', action='delResolver'),
                                params={'resolver': 'reso1'})
        print response
        assert 'Resolver u\'reso1\'  still in use' in response

        response = self.app.get(url(controller='system', action='delResolver'),
                                params={'resolver': 'reso3'})
        print response
        assert '"value": true' in response


    def test_policy_wrong_name(self):
        '''
        testing to set a policy with a wrong name
        '''
        response = self.app.get(url(controller='system', action='setPolicy'),
                                params={'name':'ads ads asd',
                                        'action':'*',
                                        'scope':'admin',
                                        'realm':'*'})
        print response
        assert 'The name of the policy may only contain the characters' in response


