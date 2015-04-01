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

        wsgiapp = pylons.test.pylonsapp
        self.app = webtest.TestApp(wsgiapp)
        self.session = 'justatest'

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


    def setUp(self):
        ''' here we do the system test init per test method '''
        #self.__deleteAllRealms__()
        #self.__deleteAllResolvers__()
        #self.__createResolvers__()
        #self.__createRealms__()

        return

    def tearDown(self):
        #self.__deleteAllRealms__()
        #self.__deleteAllResolvers__()
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
                username='admin'
                )
        return self.make_request(
            controller,
            action,
            method=method,
            params=params,
            headers=headers,
            cookies=cookies,
            )

    def make_admin_request(self, action, params=None, method='GET'):
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
            )

    def make_system_request(self, action, params=None, method='GET'):
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
            )

    def set_config_selftest(self):
        """
        Set selfTest in LinOTP Config to 'True'
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

    def __deleteAllRealms__(self):
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


    def __deleteAllResolvers__(self):
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

    def deleteAllPolicies(self):
        '''
        '''
        response = self.make_system_request('getPolicy', {})
        self.assertTrue('"status": true' in response, response)

        body = json.loads(response.body)
        policies = body.get('result', {}).get('value', {}).keys()

        for policy in policies:
            self.delPolicy(policy)

        return

    def delPolicy(self, name='otpPin'):
        params = {
            'name': name,
            }
        return self.make_system_request('delPolicy', params)

    def deleteAllTokens(self):
        ''' get all tokens and delete them '''

        serials = []

        response = self.make_admin_request('show', {})
        self.assertTrue('"status": true' in response, response)

        body = json.loads(response.body)
        tokens = body.get('result', {}).get('value', {}).get('data', {})
        for token in tokens:
            serial = token.get("LinOtp.TokenSerialnumber")
            serials.append(serial)

        for serial in serials:
            self.removeTokenBySerial(serial)

        return

    def removeTokenBySerial(self, serial):
        ''' delete a token by its serial number '''

        params = {
            'serial': serial,
            }
        response = self.make_admin_request('remove', params)
        return response

    def __createResolvers__(self):
        '''
        create all base test resolvers
        '''
        params = {
            'name'      : 'myDefRes',
            'fileName'  : '%(here)s/../data/testdata/def-passwd',
            'type'      : 'passwdresolver',
            }
        resp = self.make_system_request('setResolver', params)
        assert('"value": true' in resp)

        params = {
            'name'      : 'myOtherRes',
            'fileName'  : '%(here)s/../data/testdata/myDom-passwd',
            'type'      : 'passwdresolver',
            }
        resp = self.make_system_request('setResolver', params)
        assert('"value": true' in resp)

    def __createRealms__(self):
        '''
            Idea: build out of two resolvers
                3 realms
                - 1 per resolver
                - 1 which contains both
            Question:
                search in the mix for the user root must find 2 users
        '''

        params = {
            'realm'     :'myDefRealm',
            'resolvers' :'useridresolver.PasswdIdResolver.IdResolver.myDefRes',
        }
        resp = self.make_system_request('setRealm', params)
        assert('"value": true' in resp)

        resp = self.make_system_request('getRealms', {})
        assert('"default": "true"' in resp)

        params = {
            'realm'     :'myOtherRealm',
            'resolvers' :'useridresolver.PasswdIdResolver.IdResolver.myOtherRes',
        }
        resp = self.make_system_request('setRealm', params)
        assert('"value": true' in resp)

        params = {
            'realm'     :'myMixRealm',
            'resolvers' :'useridresolver.PasswdIdResolver.IdResolver.' +
                         'myOtherRes,useridresolver.PasswdIdResolver.' +
                         'IdResolver.myDefRes',
        }
        resp = self.make_system_request('setRealm', params)
        assert('"value": true' in resp)


        resp = self.make_system_request('getRealms', {})
        #assert('"default": "true"' in resp)

        resp = self.make_system_request('getDefaultRealm', {})
        #assert('"default": "true"' in resp)

        resp = self.make_system_request('getConfig', {})
        #assert('"default": "true"' in resp)



###eof#########################################################################

