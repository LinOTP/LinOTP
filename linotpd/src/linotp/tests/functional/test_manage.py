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


import logging
import os

try:
    import json
except ImportError:
    import simplejson

from linotp.tests import TestController, url

log = logging.getLogger(__name__)


class TestManageController(TestController):

    def setUp(self):
        '''
        resolver: reso1 (my-passwd), reso2 (my-pass2)
        realm: realm1, realm2
        token: token1 (r1), token2 (r1), token3 (r2)
        '''

        TestController.setUp(self)
        self.set_config_selftest()

        ## remove all other tokens
        self.delete_all_token()

        fixture_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'fixtures',
            )
        # create resolvers
        response = self.app.get(url(controller='system', action='setResolver'),
                                params={'name': 'reso1',
                                        'type': 'passwdresolver',
                                        'fileName': os.path.join(fixture_path,
                                                                 'my-passwd')})
        self.assertTrue('"value": true'in response, response)

        response = self.app.get(url(controller='system', action='setResolver'),
                                params={'name': 'reso2',
                                        'type': 'passwdresolver',
                                        'fileName': os.path.join(fixture_path,
                                                                 'my-pass2')})
        self.assertTrue('"value": true'in response, response)

        # create realms
        response = self.app.get(url(controller='system', action='setRealm'),
                                params={'realm': 'realm1',
                                        'resolvers':
                        'useridresolver.PasswdIdResolver.IdResolver.reso1'})

        log.info(response)
        self.assertTrue('"value": true'in response, response)

        response = self.app.get(url(controller='system', action='setRealm'),
                                params={'realm': 'realm2',
                                        'resolvers':
                        'useridresolver.PasswdIdResolver.IdResolver.reso2'})
        log.info(response)
        self.assertTrue('"value": true'in response, response)

        # create token
        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial': 'token1',
                                        'type': 'spass',
                                        'pin': 'secret',
                                        'user': 'heinz',
                                        'realm': 'realm1'
                                        })
        log.info(response)
        self.assertTrue('"value": true'in response, response)

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial': 'token2',
                                        'type': 'spass',
                                        'pin': 'secret',
                                        'user': 'nick',
                                        'realm': 'realm1'
                                        })
        log.info(response)
        self.assertTrue('"value": true'in response, response)

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial': 'token3',
                                        'type': 'spass',
                                        'pin': 'secret',
                                        'user': 'renate',
                                        'realm': 'realm2'
                                        })
        log.info(response)
        self.assertTrue('"value": true'in response, response)

    def tearDown(self):
        '''
        make the dishes
        '''
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        return TestController.tearDown(self)

    ###########################################################################
    def test_index(self):
        '''
        Manage: testing index access
        '''
        response = self.app.get(url(controller='manage', action='index'),
                                params={})
        log.info("index response: %r" % response)
        self.assertTrue('<title>LinOTP 2 Management</title>'in response,
                        response)

    def test_policies(self):
        '''
        Manage: testing policies tab
        '''
        response = self.app.get(url(controller='manage', action='policies'),
                                params={})
        log.info("policies response: %r" % response)
        self.assertTrue('<a id=policy_export>'in response, response)
        self.assertTrue('<button id=policy_import>'in response, response)
        self.assertTrue('<button id="button_policy_delete">'in response,
                        response)

    def test_audit(self):
        '''
        Manage: testing audit trail
        '''
        response = self.app.get(url(controller='manage', action='audittrail'),
                                params={})
        log.info("audit response: %r" % response)
        self.assertTrue('table id="audit_table"'in response, response)
        self.assertTrue('view_audit();'in response, response)

    def test_tokenview(self):
        '''
        Manage: testing tokenview
        '''
        response = self.app.get(url(controller='manage', action='tokenview'),
                                params={})
        log.info("token response: %r" % response)
        self.assertTrue('button_losttoken'in response, response)
        self.assertTrue('button_tokeninfo'in response, response)
        self.assertTrue('button_resync'in response, response)
        self.assertTrue('button_tokenrealm'in response, response)
        self.assertTrue('table id="token_table"'in response, response)
        self.assertTrue('view_token();'in response, response)
        self.assertTrue('tokenbuttons();' in response, response)

    def test_userview(self):
        '''
        Manage: testing userview
        '''
        response = self.app.get(url(controller='manage', action='userview'),
                                params={})
        log.info("user response: %r" % response)
        self.assertTrue('table id="user_table"' in response, response)
        self.assertTrue('view_user();' in response, response)

    def test_tokenflexi(self):
        '''
        Manage: testing the tokenview_flexi method
        '''
        response = self.app.get(url(controller='manage',
                                    action='tokenview_flexi'),
                                params={})

        testbody = response.body.replace('\n', ' ').replace('\r', '').\
                                        replace("  ", " ")
        log.info("token flexi response 1: %r" % response)
        self.assertTrue('"total": 3' in testbody, testbody)
        self.assertTrue('"token1",       true,       "heinz"' in testbody,
                                                                    testbody)
        self.assertTrue('"token2",       true,       "nick"' in testbody,
                                                                    testbody)
        self.assertTrue('"token3",       true,       "renate"' in testbody,
                                                                    testbody)

        # only renates token
        response = self.app.get(url(controller='manage',
                                    action='tokenview_flexi'),
                                params={'qtype': 'loginname',
                                        'query': 'renate'})
        testbody = response.body.replace('\n', ' ').replace('\r', '').\
                                                        replace("  ", " ")
        log.info("token flexi response 2: %r" % response)
        self.assertTrue('"total": 1' in testbody, testbody)
        self.assertTrue('"token3",       true,       "renate"' in testbody,
                                                                    testbody)

        # only tokens in realm1
        response = self.app.get(url(controller='manage',
                                    action='tokenview_flexi'),
                                params={'qtype': 'realm',
                                        'query': 'realm1'})
        log.info("token flexi response 3: %r" % response)
        self.assertTrue('"total": 2' in response, response)
        testbody = response.body.replace('\n', ' ').replace('\r', '').\
                                                            replace("  ", " ")
        self.assertTrue('"token1",       true,       "heinz"' in testbody,
                                                                    testbody)
        self.assertTrue('"token2",       true,       "nick"' in testbody,
                                                                    testbody)

        # search in all columns
        response = self.app.get(url(controller='manage',
                                    action='tokenview_flexi'),
                                params={'qtype': 'all',
                                        'query': 'token2'})
        log.info("token flexi response 4: %r" % response)
        self.assertTrue('"total": 1' in response, response)
        testbody = response.body.replace('\n', ' ').replace('\r', '').\
                                                            replace("  ", " ")
        self.assertTrue('"token2",       true,       "nick"' in testbody,
                                                                    testbody)

    def test_userflexi(self):
        '''
        Manage: testing the userview_flexi method
        '''
        # No realm, no user
        response = self.app.get(url(controller='manage',
                                    action='userview_flexi'),
                                params={})
        log.info("user flexi response 1: %r" % response)
        self.assertTrue('"total": 0' in response, response)

        # No realm, no user

        response = self.app.get(url(controller='manage',
                                    action='userview_flexi'),
                                params={"page": 1,
                                        "rp": 15,
                                        "sortname": "username",
                                        "sortorder": "asc",
                                        "query": "",
                                        "qtype": "username",
                                        "realm": "realm1"})
        log.info("user flexi response 2: %r" % response)
        self.assertTrue('"id": "heinz"' in response, response)

        response = self.app.get(url(controller='manage',
                                    action='userview_flexi'),
                                params={"page": 1,
                                        "rp": 15,
                                        "sortname": "username",
                                        "sortorder": "desc",
                                        "query": "",
                                        "qtype": "username",
                                        "realm": "realm2"})
        log.info("user flexi response 3: %r" % response)
        self.assertTrue('"id": "renate"' in response, response)

    def test_tokeninfo(self):
        '''
        Manage: Testing tokeninfo dialog
        '''
        response = self.app.get(url(controller='manage', action='tokeninfo'),
                                params={"serial": "token1"})
        log.info("tokeninfo response: %r" % response)
        self.assertTrue('class=tokeninfoOuterTable' in response, response)
        self.assertTrue('Heinz Hirtz' in response, response)
        self.assertTrue('Heinz Hirtz' in response, response)
        self.assertTrue('<td class=tokeninfoOuterTable>LinOtp.'
                        'TokenSerialnumber</td> <!-- middle column --> <td '
                        'class=tokeninfoOuterTable> token1 </td> <!-- right '
                        'column -->' in response, response)

    def test_logout(self):
        '''
        Manage: testing logout
        '''
        response = self.app.get(url(controller='manage', action='logout'),
                                params={})
        log.info("logout response: %r" % response)
        self.assertTrue('302 Found The resource was found at' in response,
                        response)
