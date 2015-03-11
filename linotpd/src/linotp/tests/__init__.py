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

from unittest import TestCase

from paste.deploy import appconfig
from paste.deploy import loadapp
from paste.script.appinstall import SetupCommand

from pylons import url
from pylons.configuration import config as env
from routes.util import URLGenerator
from webtest import TestApp
import pylons.test


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

class TestController(TestCase):
    '''
    the TestController, which loads the linotp app upfront
    '''
    def __init__(self, *args, **kwargs):
        '''
        initialize the test class
        '''

        wsgiapp = pylons.test.pylonsapp
        self.app = TestApp(wsgiapp)
        self.session = 'justatest'
        self.app.set_cookie('admin_session', self.session)

        url._push_object(URLGenerator(config['routes.map'], environ))
        TestCase.__init__(self, *args, **kwargs)

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

    def set_config_selftest(self):
        """
        Set selfTest in LinOTP Config to 'True'
        """
        params = {
            'selfTest': 'True',
            'session': self.session,
            }
        response = self.app.get(
            url(controller='system', action='setConfig'),
            params=params,
            )
        content = response.json_body
        self.assertTrue(content['result']['status'])
        self.assertTrue('setConfig selfTest:True' in content['result']['value'])
        self.assertTrue(content['result']['value']['setConfig selfTest:True'])
        self.isSelfTest = True

    def __deleteAllRealms__(self):
        ''' get al realms and delete them '''

        params = {
            'session': self.session,
            }
        response = self.app.get(
            url(controller='system', action='getRealms'),
            params=params,
            )
        jresponse = json.loads(response.body)
        result = jresponse.get("result")
        values = result.get("value", {})
        for realmId in values:
            realm_desc = values.get(realmId)
            realm_name = realm_desc.get("realmname")
            params = {
                "realm":realm_name,
                'session': self.session,
                }
            resp = self.app.get(
                url(controller='system', action='delRealm'),
                params=params,
                )
            assert('"result": true' in resp)


    def __deleteAllResolvers__(self):
        ''' get all resolvers and delete them '''

        params = {
            'session': self.session,
            }
        response = self.app.get(
            url(controller='system', action='getResolvers'),
            params=params,
            )
        jresponse = json.loads(response.body)
        result = jresponse.get("result")
        values = result.get("value", {})
        for realmId in values:
            resolv_desc = values.get(realmId)
            resolv_name = resolv_desc.get("resolvername")
            params = {
                "resolver" : resolv_name,
                'session': self.session,
                }
            resp = self.app.get(
                url(controller='system', action='delResolver'),
                params=params
                )
            assert('"status": true' in resp)

    def deleteAllPolicies(self):
        '''
        '''
        params = {
            'session': self.session,
            }
        response = self.app.get(
            url(controller='system', action='getPolicy'),
            params=params,
            )
        self.assertTrue('"status": true' in response, response)

        body = json.loads(response.body)
        policies = body.get('result', {}).get('value', {}).keys()

        for policy in policies:
            self.delPolicy(policy)

        return

    def delPolicy(self, name='otpPin', remoteurl=None):

        params = {
            'name': name,
            'selftest_admin': 'superadmin',
            'session': self.session,
            }
        r_url = url(controller='system', action='delPolicy')

        if remoteurl is not None:
            r_url = "%s/%s" % (remoteurl, "system/delPolicy")
            response = do_http(r_url, params=params)
        else:
            response = self.app.get(r_url, params=params)


        return response

    def deleteAllTokens(self):
        ''' get all tokens and delete them '''

        serials = []

        params = {
            'session': self.session,
            }
        response = self.app.get(
            url(controller='admin', action='show'),
            params=params,
            )
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
            'session': self.session,
            }

        response = self.app.get(
            url(controller='admin', action='remove'),
            params=params
            )
        return response

    def __createResolvers__(self):
        '''
        create all base test resolvers
        '''
        params = {
            'name'      : 'myDefRes',
            'fileName'  : '%(here)s/../data/testdata/def-passwd',
            'type'      : 'passwdresolver',
            'session': self.session,
            }
        resp = self.app.get(
            url(controller='system', action='setResolver'),
            params=params
            )
        assert('"value": true' in resp)

        params = {
            'name'      : 'myOtherRes',
            'fileName'  : '%(here)s/../data/testdata/myDom-passwd',
            'type'      : 'passwdresolver',
            'session': self.session,
            }
        resp = self.app.get(
            url(controller='system', action='setResolver'),
            params=params
            )
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
            'session': self.session,
        }
        resp = self.app.get(
            url(controller='system', action='setRealm'),
            params=params
            )
        assert('"value": true' in resp)

        params = {
            'session': self.session,
            }
        resp = self.app.get(
            url(controller='system', action='getRealms'),
            params=params
            )
        assert('"default": "true"' in resp)

        params = {
            'realm'     :'myOtherRealm',
            'resolvers' :'useridresolver.PasswdIdResolver.IdResolver.myOtherRes',
            'session': self.session,
        }
        resp = self.app.get(
            url(controller='system', action='setRealm'),
            params=params
            )
        assert('"value": true' in resp)

        params = {
            'realm'     :'myMixRealm',
            'resolvers' :'useridresolver.PasswdIdResolver.IdResolver.' +
                         'myOtherRes,useridresolver.PasswdIdResolver.' +
                         'IdResolver.myDefRes',
            'session': self.session,
        }
        resp = self.app.get(
            url(controller='system', action='setRealm'),
            params=params
            )
        assert('"value": true' in resp)


        params = {
            'session': self.session,
            }
        resp = self.app.get(
            url(controller='system', action='getRealms'),
            params=params,
            )
        #assert('"default": "true"' in resp)

        resp = self.app.get(
            url(controller='system', action='getDefaultRealm'),
            params=params,
            )
        #assert('"default": "true"' in resp)

        resp = self.app.get(
            url(controller='system', action='getConfig'),
            params=params,
            )
        #assert('"default": "true"' in resp)



###eof#########################################################################

