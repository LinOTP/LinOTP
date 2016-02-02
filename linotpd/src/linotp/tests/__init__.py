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
Pylons application test package

This package assumes the Pylons environment is already loaded, such as
when this script is imported from the `nosetests --with-pylons=test.ini`
command.

This module initializes the application via ``websetup`` (`paster
setup-app`) and provides the base testing objects.

"""

try:
    import json
except ImportError:
    import simplejson as json

import pylons.test
import os
import logging
import hashlib
import copy
import base64

import unittest2

from paste.deploy import appconfig
from paste.deploy import loadapp
from paste.script.appinstall import SetupCommand

from pylons import url
from pylons.configuration import config as env
from routes.util import URLGenerator
import webtest
import pylons.test
from distutils.version import LooseVersion
import pkg_resources



import warnings
warnings.filterwarnings(action='ignore', category=DeprecationWarning)

def fxn():
    warnings.warn("deprecated", DeprecationWarning)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    fxn()

LOG = logging.getLogger(__name__)

__all__ = ['environ', 'url', 'TestController']


config = pylons.test.pylonsapp.config

environ = {}



class TestController(unittest2.TestCase):
    '''
    the TestController, which loads the linotp app upfront
    '''
    def __init__(self, *args, **kwargs):
        '''
        initialize the test class
        '''
        self._version_ = {}
        self._version_['pylons'] = \
            pkg_resources.get_distribution('pylons').version

        wsgiapp = pylons.test.pylonsapp
        self.app = webtest.TestApp(wsgiapp)
        self.session = 'justatest'
        self.resolvers = {} # Set up in create_common_resolvers

        url._push_object(URLGenerator(config['routes.map'], environ))
        unittest2.TestCase.__init__(self, *args, **kwargs)

        self.appconf = config



    @classmethod
    def setup_class(cls):
        '''setup - create clean execution context by resetting database '''
        LOG.info("######## setup_class: %r" % cls)
        SetupCommand('setup-app').run([config['__file__']])
        from linotp.lib.config import refreshConfig
        refreshConfig()
        return

    @classmethod
    def teardown_class(cls):
        '''teardown - cleanup of test class execution result'''
        LOG.info("######## teardown_class: %r" % cls)
        return

    @staticmethod
    def get_json_body(response):
        """
        Parses the response body as JSON and returns it. WebOb added the property
        json_body (alias json) in version 1.2

        :param response: A WebOb response object
        """
        if response.content_type != 'application/json':
            raise ValueError(
                "Content type is not JSON. Response: %r" % response
                )
        current_webob = LooseVersion(
            pkg_resources.get_distribution('webob').version
            )
        if current_webob >= LooseVersion('1.2'):
            return response.json_body
        else:
            return json.loads(response.body, encoding=response.charset)

    @staticmethod
    def set_cookie(app, key, value):
        """
        Sets a cookie on the TestApp 'app'.
        The WebTest API changed with version 2.0.16

        :param app: A webtest.TestApp object
        """
        current_webtest = LooseVersion(
            pkg_resources.get_distribution('webtest').version
            )
        if current_webtest >= LooseVersion('2.0.16'):
            app.set_cookie(key, value)
        else:
            app.cookies[key] = value

    @staticmethod
    def get_cookies(response):
        """
        get a cookie from a response

        :param app: A webtest.TestApp object
        """
        cookies = {}
        cookie_entries = ''
        for entry in response.headerlist:
            key, val = entry
            if key == 'Set-Cookie':
                cookie_entries = val
                break

        cookys = cookie_entries.split(';')

        for cooky in cookys:
            if '=' in cooky:
                cookie_name, cookie_value = cooky.split('=', 1)
                cookies[cookie_name] = cookie_value

        return cookies

    def setUp(self):
        # here we do the system test init per test method
        #self.delete_all_realms()
        #self.delete_all_resolvers()
        #self.create_common_resolvers()
        #self.create_common_realms()

        return

    def tearDown(self):
        #self.delete_all_realms()
        #self.delete_all_resolvers()
        return

    def make_request(
            self,
            controller,
            action,
            method='GET',
            params=None,
            headers=None,
            cookies=None,
            ):
        """
        Makes a request using WebTest app self.app
        """
        assert controller and action
        assert method in ['GET', 'POST']

        # Clear state (e.g. cookies)
        self.app.reset()

        if cookies:
            for key in cookies:
                TestController.set_cookie(self.app, key, cookies[key])
        if method == 'GET':
            return self.app.get(
                url(controller=controller, action=action),
                params=params,
                headers=headers,
                )
        else:
            return self.app.post(
                url(controller=controller, action=action),
                params=params,
                headers=headers,
                )

    @staticmethod
    def get_http_digest_header(username='admin'):
        """
        Returns a string to be used as 'Authorization' in the headers
        dictionary. The values contained are basically bogus and we just aim to
        simulate how a real header would look. In production LinOTP we rely on
        Apache2 checking the authorization. In LinOTP only 'Digest username' is
        relevant.

        See for full example:
            http://en.wikipedia.org/wiki/Digest_access_authentication
        """
        # Assuming following 401 response from server:
        # 'www-authenticate': 'Digest realm="LinOTP2 admin area", nonce="hYJOfgYSBQA=6fd2875a6a04fa4fed643e5e8b0dbcbeed3930ae", algorithm=MD5, qop="auth"'
        method = 'GET'
        qop = 'auth'
        digest_uri = "/random/wont/be/checked"
        nonce = 'hYJOfgYSBQA=6fd2875a6a04fa4fed643e5e8b0dbcbeed3930ae'
        password = "randompwd"
        realm = "LinOTP2 admin area"
        nonceCount = "00000001"
        clientNonce = "0a4f113b"
        ha1 = hashlib.md5("%s:%s:%s" % (username, realm, password)).hexdigest()
        ha2 = hashlib.md5("%s:%s" % (method, digest_uri)).hexdigest()
        response = hashlib.md5(
            "%s:%s:%s:%s:%s:%s" % (
                ha1,
                nonce,
                nonceCount,
                clientNonce,
                qop,
                ha2
                )
            ).hexdigest()
        auth_content = [
            "Digest username=\"%s\"" % username,
            "realm=\"%s\"" % realm,
            "nonce=\"%s\"" % nonce,
            "uri=\"%s\"" % digest_uri,
            "qop=\"%s\"" % qop,
            "nc=\"%s\"" % nonceCount,
            "cnonce=\"%s\"" % clientNonce,
            "response=\"%s\"" % response,
            ]
        return (', ').join(auth_content)


    def make_authenticated_request(
            self,
            controller,
            action,
            method='GET',
            params=None,
            headers=None,
            cookies=None,
            auth_user='admin',
            ):
        """
        Makes an authenticated request (setting HTTP Digest header, cookie and
        'session' parameter).
        """
        params = params or {}
        headers = headers or {}
        cookies = cookies or {}
        if not 'session' in params:
            params['session'] = self.session
        if not 'admin_session' in cookies:
            cookies['admin_session'] = self.session
        if not 'Authorization' in headers:
            headers['Authorization'] = TestController.get_http_digest_header(
                username=auth_user
                )
        return self.make_request(
            controller,
            action,
            method=method,
            params=params,
            headers=headers,
            cookies=cookies,
            )

    def make_admin_request(self, action, params=None, method='GET',
                           auth_user='admin',):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            'admin',
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            )

    def make_manage_request(self, action, params=None, method='GET',
                           auth_user='admin',):
        """
        Makes an authenticated request to /manage/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            'manage',
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            )

    def make_system_request(self, action, params=None, method='GET',
                            auth_user='admin'):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            'system',
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            )

    def make_validate_request(self, action, params=None, method='GET'):
        """
        Makes an unauthenticated request to /validate/'action'
        """
        if not params:
            params = {}
        return self.make_request(
            'validate',
            action,
            method=method,
            params=params,
            )

    def set_config_selftest(self):
        """
        Set selfTest in LinOTP Config to 'True'

        --------------------------------------------------------------------
        | Should not be used and is kept to ease refactoring of old tests. |
        --------------------------------------------------------------------

        'selfTest' mode enables to use the LinOTP API without 'session'
        parameter and cookie, but since using these extra values is not a
        problem and then tests are closer to the real code running on productive
        servers it is preferred NOT to set 'selfTest'.

        Use the methods make_admin_request(), make_system_request or
        make_authenticated_request() and 'session' Parameter and Cookie will be
        set for you!

        All tests that still use set_config_selftest() should be slowly
        refactored to instead use the above mentioned methods.
        """
        params = {
            'selfTest': 'True',
            }
        response = self.make_system_request('setConfig', params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue('setConfig selfTest:True' in content['result']['value'])
        self.assertTrue(content['result']['value']['setConfig selfTest:True'])
        self.isSelfTest = True

    def delete_all_realms(self):
        ''' get al realms and delete them '''

        response = self.make_system_request('getRealms', {})
        jresponse = json.loads(response.body)
        result = jresponse.get("result")
        values = result.get("value", {})
        for realmId in values:
            realm_desc = values.get(realmId)
            realm_name = realm_desc.get("realmname")
            params = {
                "realm":realm_name,
                }
            resp = self.make_system_request('delRealm', params)
            assert('"result": true' in resp)


    def delete_all_resolvers(self):
        ''' get all resolvers and delete them '''

        response = self.make_system_request('getResolvers', {})
        jresponse = json.loads(response.body)
        result = jresponse.get("result")
        values = result.get("value", {})
        for realmId in values:
            resolv_desc = values.get(realmId)
            resolv_name = resolv_desc.get("resolvername")
            params = {
                "resolver" : resolv_name,
                }
            resp = self.make_system_request('delResolver', params)
            assert('"status": true' in resp)

    def delete_all_policies(self):
        """
        Get all policies and delete them
        """
        response = self.make_system_request('getPolicy', {})
        content = TestController.get_json_body(response)
        err_msg = "Error getting all policies. Response %s" % (content)
        self.assertTrue(content['result']['status'], err_msg)
        policies = content.get('result', {}).get('value', {}).keys()
        for policy in policies:
            self.delete_policy(policy)

        return

    def create_policy(self, params):
        """
        Create a policy. Following keys are expected in params: name, scope,
        action, user, realm, client and time

        user, realm, client and time can be omitted and will then default to *,
        *, '' and ''
        """
        lparams = {
            'user': '*',
            'realm': '*',
            'client': '',
            'time': '',
            }
        lparams.update(params)
        expected_keys = set(
            ['name', 'scope', 'action', 'user', 'realm', 'client', 'time']
            )
        assert set(lparams.keys()) == expected_keys, "Some key is missing to create a policy"
        response = self.make_system_request('setPolicy', lparams)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        expected_value = {
            u'setPolicy %s' % params['name']: {
                u'realm': True,
                u'active': True,
                u'client': True,
                u'user': True,
                u'time': True,
                u'action': True,
                u'scope': True
                }
            }
        self.assertDictEqual(expected_value, content['result']['value'])

    def delete_policy(self, name):
        """
        Delete the policy with the given name
        """
        assert name, "Policy 'name' can't be empty or None"
        params = {
            'name': name,
            }
        response = self.make_system_request('delPolicy', params)
        content = TestController.get_json_body(response)
        expected_value = {
            u'delPolicy': {
                u'result': {
                    u'linotp.Policy.%s.action' % name: True,
                    u'linotp.Policy.%s.active' % name: True,
                    u'linotp.Policy.%s.client' % name: True,
                    u'linotp.Policy.%s.realm' % name: True,
                    u'linotp.Policy.%s.scope' % name: True,
                    u'linotp.Policy.%s.time' % name: True,
                    u'linotp.Policy.%s.user' % name: True
                    }
                }
            }
        self.assertTrue(content['result']['status'])
        self.assertDictEqual(expected_value, content['result']['value'])

    def delete_all_token(self):
        """
        Get all token and delete them
        """
        serials = set()

        response = self.make_admin_request('show', params={})
        content = TestController.get_json_body(response)
        err_msg = "Error getting token list. Response %s" % (content)
        self.assertTrue(content['result']['status'], err_msg)
        data = content['result']['value']['data']
        for entry in data:
            serials.add(entry['LinOtp.TokenSerialnumber'])

        for serial in serials:
            self.delete_token(serial)

    def delete_token(self, serial):
        """
        Delete a token identified by its serial number
        """
        assert serial, "serial can not be empty or None"
        params = {
            'serial': serial,
            }
        response = self.make_admin_request('remove', params=params)
        content = TestController.get_json_body(response)
        err_msg = "Error deleting token %s. Response %s" % (serial, content)
        self.assertTrue(content['result']['status'], err_msg)
        self.assertEqual(1, content['result']['value'], err_msg)

    def create_common_resolvers(self):
        """
        Create 2 PasswdIdResolvers named myDefRes and myOtherRes
        """

        resolver_params = {
            'myDefRes': {
                'name'      : 'myDefRes',
                'fileName'  : '%(here)s/../data/testdata/def-passwd',
                'type'      : 'passwdresolver',
                },
            'myOtherRes' : {
                'name'      : 'myOtherRes',
                'fileName'  : '%(here)s/../data/testdata/myDom-passwd',
                'type'      : 'passwdresolver',
                }
            }
        self.resolvers = {
            'myOtherRes': 'useridresolver.PasswdIdResolver.IdResolver.myOtherRes',
            'myDefRes': 'useridresolver.PasswdIdResolver.IdResolver.myDefRes',
            }
        params = resolver_params['myDefRes']
        response = self.create_resolver(
            name='myDefRes',
            params=params,
            )
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])

        params = resolver_params['myOtherRes']
        response = self.create_resolver(
            name='myOtherRes',
            params=params,
            )
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])

    def create_resolver(self, name, params):
        param = copy.deepcopy(params)
        param['name'] = name
        resp = self.make_system_request('setResolver', param)
        return resp

    def create_realm(self, realm, resolvers):

        params = {}
        params['realm'] = realm

        if type(resolvers) == list:
            params['resolvers'] = ','.join(resolvers)
        else:
            params['resolvers'] = resolvers

        resp = self.make_system_request('setRealm', params)
        return resp

    def create_common_realms(self):
        """
            Idea: build out of two resolvers
                3 realms
                - 1 per resolver
                - 1 which contains both
            Question:
                search in the mix for the user root must find 2 users
        """

        # Create 'myDefRealm' realm
        response = self.create_realm(
            realm='myDefRealm',
            resolvers=self.resolvers['myDefRes'],
            )
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])

        # Create 'myOtherRealm' realm
        response = self.create_realm(
            realm='myOtherRealm',
            resolvers=self.resolvers['myOtherRes'],
            )
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])

        # Create mixed realm
        response = self.create_realm(
            realm='myMixRealm',
            resolvers=','.join(self.resolvers.values()),
            )
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])

        # Assert 'myDefRealm' is default
        response = self.make_system_request('getRealms', {})
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        realms = content['result']['value']
        self.assertEqual(len(realms), 3)
        self.assertIn('mydefrealm', realms)
        self.assertIn('default', realms['mydefrealm'])
        self.assertTrue(realms['mydefrealm']['default'])

    def _user_service_init(self, auth_user, password):

        passw = ':' + base64.b32encode(password)
        params = {'login': auth_user, 'password': passw}
        response = self.app.get(url(controller='userservice',
                                    action='auth'), params=params)

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('userauthcookie')
        if not auth_cookie:
            pass
        self.assertIsNotNone(auth_cookie, "%r:%r" % (response, cookies))

        self.user_service[auth_user] = auth_cookie

        return auth_cookie

    def make_userservice_request(self, action, params=None,
                                 auth_user=None):

        if not params:
            params = {}

        if not hasattr(self, 'user_service'):
            setattr(self, 'user_service', {})

        user, password = auth_user
        auth_cookie = self.user_service.get(user,
                                    self._user_service_init(user, password))
        TestController.set_cookie(self.app, 'userauthcookie', auth_cookie)

        params['session'] = auth_cookie
        params['user'] = user
        response = self.app.get(url(controller='userservice',
                                    action=action),
                                params=params)

        return response




###eof#########################################################################

