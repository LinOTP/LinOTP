# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
Test the support for resolver definitions in system or admin policy user entry
"""
import base64

import logging
from linotp.tests import TestController, url

log = logging.getLogger(__name__)


class TestSelfserviceAuthController(TestController):

    def setUp(self):
        TestController.setUp(self)
        # clean setup
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()
        self.create_extra_resolver()

    def tearDown(self):
        TestController.tearDown(self)
        pass

    def create_extra_resolver(self):
        resolver_params = {
            'adminResolver': {
                'name': 'adminResolver',
                'fileName': '%(here)s/../data/testdata/admin-passwd',
                'type': 'passwdresolver',
                },
            }
        self.resolvers = {
            'adminResolver': ('useridresolver.PasswdIdResolver.'
                              'IdResolver.adminResolver'),
            }
        params = resolver_params['adminResolver']
        response = self.create_resolver(name='adminResolver', params=params)
        self.assertTrue('"status": true' in response, response)

    def createPolicy(self, param=None):
        policy = {'name': 'self01',
                  'scope': 'selfservice',
                  'realm': 'myDefRealm',
                  'user': None,
                  'action': 'history',
                }

        # overwrite the default defintion
        if not param:
            param = {}
        policy.update(param)
        name = policy['name']

        response = self.make_system_request('setPolicy', params=policy)
        self.assertTrue('"status": true' in response, response)
        self.assertTrue(('"setPolicy %s": {' % name) in response, response)

###############################################################################

    def test_selfservice_user_resolver(self):
        '''
        Selfservice Authorization: test for wildcard user resolver with attribute existance

        1 define policy with wildcad in username and attribute test
        2. check for wildcard matching user with attribute
        3  other user is not allowed
        4. add other user to the policy
        5  check is now valid for other* user
        '''
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': ' passthru.*.myDefRes:#mobile, ',
                  'realm': '*'
                 }
        self.createPolicy(policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        # check for not beeing part of this resolver
        auth_user = ('other_user@myotherrealm', 'geheim2')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        msg = "policy settings do not allow you to issue this request!"
        self.assertTrue(msg in response, response)

        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': (' passthru.*.myDefRes:#mobile~=1234-24, '
                           ' other_user.*.myOtherRes:#userid, '),
                  'realm': '*'
                 }
        self.createPolicy(policy)

        # for other user: check if policy is defined
        auth_user = ('other_user@myotherrealm', 'geheim2')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')

    def test_selfservice_resolver_attribute(self):
        '''
        Selfservice Authorization: test for resolver with attribute comparison
        '''
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': ' myDefRes:#mobile~=1234-24, ',
                  'realm': '*'
                 }
        self.createPolicy(policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        # check for not beeing part of this resolver
        auth_user = ('other_user@myotherrealm', 'geheim2')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        msg = "policy settings do not allow you to issue this request!"
        self.assertTrue(msg in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')

    def test_selfservice_resolver(self):
        '''
        Selfservice Authorization: test for resolver with attribute comparison
        '''
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': ' .*.myDefRes:',
                  'realm': '*'
                  }
        self.createPolicy(policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        # check for not beeing part of this resolver
        auth_user = ('other_user@myotherrealm', 'geheim2')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        msg = "policy settings do not allow you to issue this request!"
        self.assertTrue(msg in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')


    def test_selfservice_enable_disable_service(self):
        '''
        Selfservice Authorization: test of attribute in policies to enables service

        1. defined is the mobile attribute contains-comparison for the
           hmac token enrollment only.
        2. check that history action does not work
        3. after adding the history to the policy defintion, check that
           history sction works
        '''

        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': ' #mobile~=1234-24, ',
                  'realm': '*'
                 }
        self.createPolicy(policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        params = {'page': '1', 'pg': '3'}
        response = self.make_userservice_request('history',
                                                 params=params,
                                                 auth_user=auth_user)
        msg = "policy settings do not allow you to issue this request!"
        self.assertTrue(msg in response, response)

        policy = {'name': 'T1',
                  'action': 'enrollHMAC, history ',
                  'user': ' #mobile~=1234-24, ',
                  'realm': '*'
                 }
        self.createPolicy(policy)

        params = {'page': '1', 'pg': '3'}
        response = self.make_userservice_request('history',
                                                 params=params,
                                                 auth_user=auth_user)

        self.assertTrue('"rows": [' in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')

    def test_selfservice_regex_userdomain(self):
        '''
        Selfservice Authorization: regex domain user comparison with attribute contains comparison

        1.  define policy with attribute filte on username wildcard and domain
            and regex username domain filter
        2. check that attribute filter works
        3. check that regex user domain filter works
        '''
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': (' passthru.*@myDefRealm#mobile~=1234-24, '
                           ' other.*@myotherRealm'),
                  'realm': '*',
                 }
        self.createPolicy(policy)

        # check for regex match of user
        auth_user = ('other_user@myotherrealm', 'geheim2')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')

    def test_selfservice_attribute_contains(self):
        '''
        Selfservice Authorization: attribute only comparison with partial value match

        1 define policy with attribute filter on partial string match
        2 check for one user with attribute that he is allowed
        3. other user is not allowed as attribute
        '''
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': ' #mobile~=1234-24, '
                 }
        self.createPolicy(policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        # for passthru_user1 do check if policy is defined
        auth_user = ('shakespeare@myDefRealm', 'shakespeare1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        msg = "policy settings do not allow you to issue this request!"
        self.assertTrue(msg in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')

    def test_selfservice_attribute_equal(self):
        '''
        Selfservice Authorization: attribute comparison with exact match

        1 define policy with attribute filter on exact string match
        2 check for one user with attribute that he is allowed
        3. other user is not allowed as attribute
        '''
        # the user defintion to mach the attribute in user only
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': ' #mobile == +49(0)1234-24, '
                 }
        self.createPolicy(policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        self.assertTrue('"img": "<img ' in response, response)

        # for passthru_user1 do check if policy is defined
        auth_user = ('shakespeare@myDefRealm', 'shakespeare1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        msg = "policy settings do not allow you to issue this request!"
        self.assertTrue(msg in response, response)

        self.delete_policy('T1')
        self.delete_token('hmac123')

