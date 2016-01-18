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


class TestAdminAuthController(TestController):

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
        return

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

        return

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

        return

###############################################################################
    def test_admin_show(self):
        '''
        Admin Authorization: The admin is verified to be part of an resolver definition
        '''
        parameters = {'name': 'admin_auth_show',
                      'scope': 'admin',
                      'realm': 'myOtherRealm',
                      'action': 'userlist, show',
                      'user': 'admin, adminResolver:, *@virtRealm',
                      }
        response = self.make_system_request('setPolicy', params=parameters)

        self.assertTrue('"status": true' in response, response)

        parameters = {}

        # simple match - backward compatibility
        response = self.make_admin_request('show', params=parameters,
                                           auth_user='admin')
        self.assertTrue('"status": true' in response, response)

        # pattern match for domain
        response = self.make_admin_request('show', params=parameters,
                                           auth_user='root@virtRealm')
        self.assertTrue('"status": true' in response, response)

        # existance test in resolver
        response = self.make_admin_request('show', params=parameters,
                                           auth_user='root@adomain')
        self.assertTrue('"status": true' in response, response)

        # non existance test in resolver
        response = self.make_admin_request('show', params=parameters,
                                           auth_user='toor@adomain')
        self.assertTrue('"status": false' in response, response)

        return

    def test_admin_userlist(self):
        '''
        Admin Authorization: The admin is verified to be part of an resolver definition
        '''
        parameters = {'name': 'admin_auth_userlist',
                      'scope': 'admin',
                      'realm': 'myOtherRealm',
                      'action': 'userlist',
                      'user': 'admin, adminResolver:, *@virtRealm',
                      }
        response = self.make_system_request('setPolicy', params=parameters)

        self.assertTrue('"status": true' in response, response)

        # simple match - backward compatibility
        parameters = {'username': '*', 'resConf': 'myOtherRes'}
        response = self.make_admin_request('userlist', params=parameters,
                                           auth_user='admin')
        self.assertTrue('"status": true' in response, response)

        # widcard match for realm user
        parameters = {'username': '*', 'resConf': 'myOtherRes'}
        response = self.make_admin_request('userlist', params=parameters,
                                           auth_user='root@virtRealm')
        self.assertTrue('"status": true' in response, response)

        # resolver match
        parameters = {'username': '*', 'resConf': 'myOtherRes'}
        response = self.make_admin_request('userlist', params=parameters,
                                           auth_user='root@adomain')
        self.assertTrue('"status": true' in response, response)

        # resolver mis match
        response = self.make_admin_request('userlist', params=parameters,
                                           auth_user='toor@adomain')
        self.assertTrue('"status": false' in response, response)

        return

    def test_system_auth(self):
        """
        System Authorization: check if root from resolver myDefRes: is allowed to write
        """
        parameters = {'name': 'sysSuper',
                      'scope': 'system',
                      'realm': '*',
                      'action': 'read, write',
                      'user': 'superadmin, adminResolver:, *@virtRealm',
                      }
        response = self.make_system_request('setPolicy', params=parameters,
                                            auth_user='superadmin')
        self.assertTrue('"status": true' in response, response)

        try:
            parameters = {'name': 'sys_auth',
                          'scope': 'system',
                          'realm': '*',
                          'action': 'read',
                          'user': 'admin',
                          }
            response = self.make_system_request('setPolicy', params=parameters,
                                                auth_user='superadmin')
            self.assertTrue('"status": true' in response, response)

            # now do rhe test on setConfig
            params = {'testKey': 'testVal'}
            response = self.make_system_request('setConfig', params=params,
                                                auth_user='root@virtRealm')
            self.assertTrue('"status": true' in response, response)

            # now do rhe test on setConfig
            params = {'testKey': 'testVal'}
            response = self.make_system_request('setConfig', params=params,
                                                auth_user='root@adomain')
            self.assertTrue('"status": true' in response, response)

            # deny as not found in resolver or local match
            params = {'testKey': 'testVal'}
            response = self.make_system_request('setConfig', params=params,
                                                auth_user='admin')
            self.assertTrue('Policy check failed. You are not '
                            'allowed to write system config.' in response,
                            response)

            # now do rhe test on setConfig
            params = {'testKey': 'testVal'}
            response = self.make_system_request('setConfig', params=params,
                                                auth_user='superadmin')
            self.assertTrue('"status": true' in response, response)

        finally:
            parameters = {'name': 'sys_auth'}
            response = self.make_system_request('delPolicy', params=parameters,
                                            auth_user='superadmin')
            self.assertTrue('"status": true' in response, response)

            parameters = {'name': 'sysSuper'}
            response = self.make_system_request('delPolicy', params=parameters,
                                            auth_user='superadmin')
            self.assertTrue('"status": true' in response, response)

        return
