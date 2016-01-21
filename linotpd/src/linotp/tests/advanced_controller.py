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
Added new test-controller (called advanced test controller)

The new test-controller was designed as an improvement of the
existing one, with the idea to better support readability and
clients written in different programming languages (based on
this new controller we will implement portable test cases).

The new controller will hide the technical details about how to
perform LinOTP calls (pillons, authentication) and will provide
methods for direct LinOTP operations. The writer of test cases
does not need to understand how the communication works, he
only need to know the LinOTP interface-api and directly perform
the operations which are needed in tests. More, the new
controller will provide better support for checking the return
values and in all of the cases the result values are tested by
default (for success).
"""

import unittest2
import warnings
import json
import re

import pkg_resources
from distutils.version import LooseVersion

from pylons import url

from linotp.tests                  import TestController
from linotp.tests.tools.json_utils import JsonUtils


#import logging
#log = logging.getLogger(__name__)

#
# In modern languages like C, C++, C#, it is very useful to use conditional macros.
# This feature is not available in Python but it can be simulated with attributes
# attached to "builtin" module.
# In this particular case, the "use_standalone_advanced_controller" attribute is
# used to detach advanced-controller from other dependencies (standard controller;
# requirement needed for portable test cases).
#
import __builtin__
if not getattr(__builtin__, 'use_standalone_advanced_controller', False):
    from linotp.tests import TestController
    class TestController2(TestController):
        def __init__(self, *args, **kwargs):
            super(TestController2, self).__init__(*args, **kwargs)
        pass
else:
    class TestController2(unittest2.TestCase):
        def __init__(self, *args, **kwargs):
            super(TestController2, self).__init__(*args, **kwargs)

            # In case we detach controller from previous standard version,
            # we need to implement (at least for short amount of time)
            # support for Pylons and WebTest.
            import webtest
            import pylons.test
            from routes.util import URLGenerator

            environ = {}
            wsgiapp = pylons.test.pylonsapp
            config = pylons.test.pylonsapp.config

            self.app = webtest.TestApp(wsgiapp, environ)
            self.session = 'justatest'
            #self.appconf = config

            # Configure url ...
            url._push_object(URLGenerator(config['routes.map'], environ))



# This is an utility class used to "seal" class implementation (forbid inheritance).
class Final(type):
    def __new__(cls, name, bases, classdict):
        for b in bases:
            if isinstance(b, Final):
                raise TypeError("type '{0}' is not an acceptable base type".format(b.__name__))
        return type.__new__(cls, name, bases, dict(classdict))
    
# The class DefaultValue is used internally by TestAdvancedController as 
# placeholder for default values for all methods where expectedValue is used.
class DefaultValue:
    __metaclass__ = Final



class TestAdvancedController(TestController2):
    def __init__(self, *args, **kwargs):
        super(TestAdvancedController, self).__init__(*args, **kwargs)
        self._headers = None
        self._cookies = None
        self._gparams = None

    def setUp(self):
        super(TestAdvancedController, self).setUp()
        # On startup, initialize the session cookie...
        self.Cookies['session'] = self.session
        
    def tearDown(self):
        self.setAuthorization(None)
        # On finish, delete the session variable...
        self.Cookies['session'] = None
        super(TestAdvancedController, self).tearDown()


    # Headers is a very useful class to simulate Http Request headers.
    class HeadersWrapper:
        def __init__(self):
            self._dict = {}
        def __getitem__(self, name):
            return self._dict[name]
        def __setitem__(self, name, value):
            if not value is None:
                self._dict[name] = value
            elif name in self._dict:
                del self._dict[name]
        def __delitem__(self, name):
            if name in self._dict: del self._dict[name]
        def get(self):
            return self._dict

    # The Headers property is a collection of name-values which
    # is passed through with each Http-Requests. If user requires
    # authentication. the Headers is the right place to set the
    # authentication token.
    @property
    def Headers(self):
        if self._headers is None:
            self._headers = TestAdvancedController.HeadersWrapper()
        return self._headers

    # The GlobalParams property is a collection of name-values which
    # is passed through with each Requests as extra "Query" values.
    # If user requires to pass a constant query string into each
    # web request (like session key), this is the right place to
    # place your information.
    @property
    def GlobalParams(self):
        if self._gparams is None:
            self._gparams = TestAdvancedController.HeadersWrapper()
        return self._gparams

    # CookieWrapper is a class which better simulates session Cookies.
    # This class does not overwrite existing implementation, this class
    # is only an extra layer of abstraction.
    class CookiesWrapper:
        def __init__(self, app):
            self.app = app
        def __getitem__(self, name):
            return self.app.Cookie[name]
        def __setitem__(self, name, value):
            if value is None: value = ''
            current_webtest = LooseVersion(pkg_resources.get_distribution('webtest').version)
            if current_webtest >= LooseVersion('2.0.16'):
                self.app.set_cookie(name, value)
            else:
                self.app.cookies[name] = value
        def __delitem__(self, name):
            self.__setitem__(name, None)

    # The property Cookies provides easy access to internal Cookies.
    @property
    def Cookies(self):
        if self._cookies is None:
            self._cookies = TestAdvancedController.CookiesWrapper(self.app)
        return self._cookies

    # This static-method is used to merge multiple dictionaries...
    @staticmethod
    def appendDict(initialDict, *anotherDict):
        if initialDict is None:
            initialDict = {}
        for temp in anotherDict:
            if not temp is None:
                initialDict.update(temp)
        return initialDict;


    # Return a predefined authentication token. The security token is
    # taken from the standard TestController!
    def getDefaultAuthorization(self):
        return TestController.get_http_digest_header(username='admin')

    # Setup web-api credential information (use None for clear).
    def setAuthorization(self, authorization, session=None):
        if authorization is None:
            self.GlobalParams['session']  = None
            self.Cookies['admin_session'] = None
            self.Headers['Authorization'] = None
        else:
            self.GlobalParams['session']  = session or self.session
            self.Cookies['admin_session'] = session or self.session
            self.Headers['Authorization'] = authorization
        return


    # Invoke LinOTP web-api wrapper. This method has validation support,
    # which is able to check for an exact value (or a predefined set of
    # dictionary entries).
    # Supplementary, this method has support for regular-expressions,
    # which also compare name-captures against the current request parameters.
    def invokeLinotp(self, linotpController, linotpAction,
                     expectedValue=None, valueErrorMessage=None, passResponse=False,
                     headers=None, **params):
        # Append dictionaries and convert all unicode names or values
        # to predefined encoded string (in praxis utf-8).
        def encodeDict(encoding, *anotherDict):
            retDict = {}
            for temp in anotherDict:
                if not temp is None:
                    for key in temp.keys():
                        value = temp[key]
                        if isinstance(key,   unicode):
                            key   = key.encode(encoding)
                        if isinstance(value, unicode):
                            value = value.encode(encoding)
                        elif not isinstance(value, basestring):
                            value = str(value)   
                             
                        retDict[key] = value
            return retDict;

        # By default we perform only get requests
        postMethod = False
        if 'method' in params:
            # Allow only get and post methods!
            self.assertTrue(params['method'].lower() in ['get', 'post'],
                            "Invalid or unsupported Web method: " + params['method'])
            postMethod = params['method'] == 'post'

        # Process params and headers...
        #     We do not allow transport of Unicode strings. If Unicode string
        #     is provided, we convert the unicode value to utf-8 string!
        req_params  = encodeDict('utf-8', self.GlobalParams.get(), params)
        req_headers = encodeDict('utf-8', self.Headers.get(),      headers)

        # Perform the web-request...
        if postMethod:
            rsp = self.app.post(
                    url(controller=linotpController, action=linotpAction),
                    params=req_params, headers=req_headers)
        else:
            rsp = self.app.get(
                    url(controller=linotpController, action=linotpAction),
                    params=req_params, headers=req_headers)

        # The web-request must not fail!
        self.assertEqual(rsp.status_int, 200, rsp.status)

        # The result is always json!
        res = JsonUtils.getBody(rsp)  # rsp.json_body
        # result Status must be always True!
        self.assertTrue(JsonUtils.getJson(res, ['result', 'status']) == True,
            ("Failed LinOTP %s.%s invocation (result: %s)" 
                % (linotpController, linotpAction, str(rsp))))
        value = JsonUtils.getJson(res, ['result', 'value'])
        if value is None:
            self.fail(
                ("The LinOTP %s.%s invocation returned no value (result: %s)" 
                    % (linotpController, linotpAction, str(rsp))))
        elif not expectedValue is None:
            # If an explicit value is expected, then we compare the value
            if not JsonUtils.checkJsonValues(value, expectedValue, params):
                # Ups, the invocation failed!
                if valueErrorMessage is None or len(valueErrorMessage) == 0:
                    valueErrorMessage = ('Unexpected LinOTP %s.%s invocation'
                                         ' value: %s (expected was: %s)'
                        % (linotpController, linotpAction, str(value),
                           str(expectedValue)))
                self.fail(valueErrorMessage)
        else:
            if passResponse is None or \
               isinstance(passResponse, bool):
                if passResponse:
                    return res
                else:
                    # If no value is expected and the full response is not needed,
                    # then return only the value!
                    return value
            else:
                # return both value and passResponse lookup value..
                return (value, JsonUtils.getJson(res, passResponse))
        
        if passResponse is None or \
           isinstance(passResponse, bool):
            if passResponse:
                # return full response
                return res
            else:
                pass # return nothing
        else:
            # value is Ok, then return only the passResponse lookup value...
            return JsonUtils.getJson(res, passResponse)


    # *********************************************************************
    # Start of LinOTP wrapped api...
    # ---------------------------------------------------------------------
    # Here, are located only calls to LinOTP server. By default all return
    # values are validated against a default (expected) value.
    # *********************************************************************

    #region Configuration wrappers
    def getConfiguration(self, key=None, defaultValue=None,
                         **extraParams):
        res = self.invokeLinotp('system', 'getConfig',
                                expectedValue={}, # dictionary expected.
                                **extraParams)
        if not key is None:
            path = [] #['result', 'value']
            if isinstance(key, list):
                path.extend(key)
            else: 
                path.append(key)
            return JsonUtils.getJson(res, path, defaultValue)
            
        inf = JsonUtils.getJson(res, ['result', 'value'])
        if defaultValue is None:
            return inf
        return TestAdvancedController.appendDict(defaultValue, inf)

    def setConfiguration(self, key, value,
                         expectedValue=DefaultValue,
                         **extraParams):
        if not value is None:
            if expectedValue is DefaultValue:
                expectedValue = {re.compile('^setConfig (?P<key>.*)$'): True}
            params          = extraParams
            params['key']   = key
            params['value'] = value
            self.invokeLinotp('system', 'setConfig',
                              expectedValue=expectedValue,
                              **params)
        else:
            if expectedValue is DefaultValue:
                expectedValue = {re.compile('^delConfig (?P<key>.*)$'): True}
            self.invokeLinotp('system', 'delConfig',
                              key=key,
                              expectedValue=expectedValue)

    def deleteConfiguration(self, key, 
                            expectedValue=DefaultValue):
        if expectedValue is DefaultValue:
            expectedValue = {re.compile('^delConfig (?P<key>.*)$'): True}
        self.invokeLinotp('system', 'delConfig',
                          key=key,
                          expectedValue=expectedValue)
    #endregion

    #region Resolver support
    def createResolver(self, name, type,
                       expectedValue=DefaultValue, valueErrorMessage=None,
                       **params):
        if expectedValue is DefaultValue:
            expectedValue = True
        return self.invokeLinotp('system', 'setResolver',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 name=name, type=type,
                                 **params)
        
    def deleteResolver(self, name,
                       expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = True
        return self.invokeLinotp('system', 'delResolver',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 resolver=name)
        
    def getResolvers(self, defaultValue={}, **extraParams):
        ''' get all resolvers and delete them '''
        res = self.invokeLinotp('system', 'getResolvers',
                                 expectedValue=None,
                                 **extraParams)
        if res is None:
            return defaultValue
        return res #JsonUtils.getJson(res, ['result', 'value'], defaultValue)
    
    def getResolverUsers(self, resolver, username=None, defaultValue={},
                         **extraParams):
        res = self.invokeLinotp('admin', 'userlist',
                                resConf=resolver, username=username or '*',
                                **extraParams)
        if res is None:
            return defaultValue
        return res #JsonUtils.getJson(res, ['result', 'value'], defaultValue)
    #endregion


    #region Realm support
    def createRealm(self, name, resolvers,
                    expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = True
        return self.invokeLinotp('system', 'setRealm',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 realm=name, resolvers=resolvers)
    
    def deleteRealm(self, name,
                    expectedValue=DefaultValue,
                    valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = {'delRealm': {'result': True}}
        return self.invokeLinotp('system', 'delRealm',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 realm=name)
    
    def getRealms(self, defaultValue={}, **extraParams):
        res = self.invokeLinotp('system', 'getRealms',
                                 expectedValue=None,
                                 **extraParams)
        if res is None:
            return defaultValue
        return res #JsonUtils.getJson(res, ['result', 'value'], defaultValue)
    
    def getRealmUsers(self, realm, username=None, defaultValue={},
                      **extraParams):
        res = self.invokeLinotp('admin', 'userlist',
                                realm=realm, username=username or '*',
                                **extraParams)
        if res is None:
            return defaultValue
        return res #JsonUtils.getJson(res, ['result', 'value'], defaultValue)
    #endregion

    #region Policy support
    def createPolicy(self, name, scope, action,
                     expectedValue=DefaultValue, valueErrorMessage=None,
                     **params):
        if expectedValue is DefaultValue:
            expectedValue = {
                re.compile('^setPolicy (?P<name>.*)$'): {
                    'realm' : True,
                    'active': True,
                    'client': True,
                    'user'  : True,
                    'time'  : True,
                    'action': True,
                    'scope' : True
                }
            }
        parameters = {
            'name'  : name,
            'scope' : scope,
            'action': action,
            'user'  : '*',
            'realm' : '*',
            'client': '',
            'time'  : ''
        }
        parameters.update(params)
        return self.invokeLinotp('system', 'setPolicy',
                                 expectedValue=expectedValue,
                                 valueErrorMesage=valueErrorMessage,
                                 **parameters)
        
    def deletePolicy(self, name,
                     expectedValue=DefaultValue,
                     valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = {
                'delPolicy': {
                    'result': {
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.action$'): True,
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.active$'): True,
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.client$'): True,
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.realm$') : True,
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.scope$') : True,
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.time$')  : True,
                        re.compile('^linotp\.Policy\.(?P<name>.*)\.user$')  : True
                    }
                }
            }
        return self.invokeLinotp('system', 'delPolicy',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 name=name)
        
    def getPolicies(self, defaultValue={}, **extraParams):
        res = self.invokeLinotp('system', 'getPolicy',
                                 expectedValue=None,
                                 **extraParams)
        if res is None:
            return defaultValue
        return res #JsonUtils.getJson(res, ['result', 'value'], defaultValue)
    #endregion

    #region Token support
    def createToken(self,
                    expectedValue=DefaultValue, valueErrorMessage=None,
                    **params):
        if expectedValue is DefaultValue:
            expectedValue = True
        parameters = TestAdvancedController.appendDict({}, params)
        if 'serial' is params and not 'description' in params:
            parameters['description'] = "TestToken " + params['serial']
        if expectedValue is None:
            (val, res) = self.invokeLinotp('admin', 'init',
                                           expectedValue=None,
                                           valueErrorMessage=valueErrorMessage,
                                           passResponse=['detail'],
                                           **parameters)
            if val == True:
                return res
            else:
                return None
        
        return self.invokeLinotp('admin', 'init',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 passResponse=['detail'],
                                 **parameters)
        
    def assignToken(self, serial, user, pin=None, realm=None,
                    expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = True
        parameters = {'serial': serial, 'user': user}
        if not pin is None:
            parameters['pin'] = pin
        if not realm is None:
            parameters['realm'] = realm
        return self.invokeLinotp("admin", "assign",
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 **parameters)
        
    def enableToken(self, serial,
                    expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = 1
        return self.invokeLinotp("admin", "enable",
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 serial=serial)
        
    def disableToken(self, serial,
                    expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = 1
        return self.invokeLinotp("admin", "disable",
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 serial=serial)

    def removeTokenBySerial(self, serial,
                            expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = 1
        return self.invokeLinotp('admin', 'remove',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 serial=serial)

    def removeTokenByUser(self, user,
                          expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = 1
        return self.invokeLinotp('admin', 'remove',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 user=user)

    def getTokenOwner(self, serial,
                      expectedValue=DefaultValue,
                      valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = {'username': re.compile('.*')}
        return self.invokeLinotp('admin', 'getTokenOwner',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 serial=serial)
        
    def setTokenRealm(self, serial, realm,
                      expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = 1
        return self.invokeLinotp('admin', 'tokenrealm',
                                 expectedValue=expectedValue,
                                 valueErrorMesage=valueErrorMessage,
                                 serial=serial, realms=realm)
        
    def getTokens(self, defaultValue={}, **extraParams):
        res = self.invokeLinotp('admin', 'show',
                                 expectedValue=None,
                                 **extraParams)
        if res is None:
            return defaultValue
        return res #JsonUtils.getJson(res, ['result', 'value'], defaultValue)
    #endregion

    def validateCheck(self, user, password, realm=None,
                     expectedValue=DefaultValue, valueErrorMessage=None):
        if expectedValue is DefaultValue:
            expectedValue = True
        parameters = {'user': user,
                      'pass': password }
        if not realm is None:
            parameters['realm'] = realm
        if expectedValue is None:
            (val, res) = self.invokeLinotp('validate', 'check',
                                           expectedValue=expectedValue,
                                           valueErrorMessage=valueErrorMessage,
                                           passResponse=['details'],
                                           **parameters)
            if val == True:
                return res
            else:
                return None
            
        return self.invokeLinotp('validate', 'check',
                                 expectedValue=expectedValue,
                                 valueErrorMessage=valueErrorMessage,
                                 passResponse=['details'],
                                 **parameters)            


    # *********************************************************************
    # Start of LinOTP test api...
    # ---------------------------------------------------------------------
    # Here, are located only calls to LinOTP server which are designed to
    # initialize the test environment.
    # *********************************************************************

    # initialize selftest...
    def setConfigSelfTest(self, selfTest=True):
        if selfTest:
            warnings.warn("The self-test modus is not recommended (anymore)!")
            self.invokeLinotp('system', 'setConfig',
                              expectedValue={'setConfig selfTest:True': True},
                              selfTest=True)
        else:
            self.invokeLinotp('system', 'setConfig',
                              expectedValue={'setConfig selfTest:False': True},
                              selfTest=False)

    # create default objects...
    def createDefaultResolvers(self):
        """
        Create 2 PasswdIdResolvers named myDefRes and myOtherRes
        """
        resolver_infos = [{
                'name'     : 'myDefRes',
                'type'     : 'passwdresolver',
                'fileName' : '%(here)s/../data/testdata/def-passwd'
            }, {
                'name'     : 'myOtherRes',
                'type'     : 'passwdresolver',
                'fileName' : '%(here)s/../data/testdata/myDom-passwd'
            }]
        for resolver in resolver_infos:
            self.createResolver(name=resolver['name'],
                                type=resolver['type'],
                                fileName=resolver['fileName'])
            
    def createDefaultRealms(self):
        """
            Idea: build out of two resolvers
                3 realms
                - 1 per resolver
                - 1 which contains both
            Question:
                search in the mix for the user root must find 2 users
        """
        realm_infos = [{
                'name'       : 'myDefRealm',
                'resolver'   : 'myDefRes',
                'resolverId' : 'useridresolver.PasswdIdResolver.IdResolver.myDefRes'
            }, {
                'name'       : 'myOtherRealm',
                'resolver'   : 'myOtherRes',
                'resolverId' : 'useridresolver.PasswdIdResolver.IdResolver.myOtherRes'
            }]
        # Create mixed realm
        realm_infos.append({
                'name'       : 'myMixRealm',
                'resolverId' : ','.join(map(lambda r: r['resolverId'], realm_infos))
            })
        for realm in realm_infos:
            # Create test realms
            self.createRealm(name      = realm['name'],
                             resolvers = realm['resolverId'])

        realms = self.getRealms()
        errmsg = 'Internal error, program not properly initialized'
        self.assertIsInstance(realms, dict)
        if not (sorted(realms.keys()) == sorted(['mydefrealm', 'myotherrealm', 'mymixrealm'])):
            for realm in ['mydefrealm', 'myotherrealm', 'mymixrealm']:
                self.assertIn(realm, realms.keys(), 'Expected realm not available: ' + realm)
            warnings.warn('A non-expected list of realms returned')
                
        # Assert 'myDefRealm' is default
        self.assertIn('default', realms['mydefrealm'],   errmsg)
        self.assertTrue(realms['mydefrealm']['default'], errmsg)

    # clear installation (delete all objects)...
    def deleteAllResolvers(self):
        ''' get all resolvers and delete them '''
        data = self.getResolvers()
        for realmId in data.keys():
            resolver = data[realmId]
            self.deleteResolver(name=resolver['resolvername'])

    def deleteAllRealms(self):
        ''' get all realms and delete them '''
        data = self.getRealms()
        for realmId in data.keys():
            realm = data[realmId]
            self.deleteRealm(name=realm['realmname'])

    def deleteAllPolicies(self):
        ''' get all policies and delete them '''
        data = self.getPolicies()
        for policy in data.keys():
            self.deletePolicy(name=policy)

    def deleteAllTokens(self):
        ''' get all tokens and delete them '''
        vals = self.getTokens()
        data = JsonUtils.getJson(vals, ['data'])
        for token in data:
            self.removeTokenBySerial(serial=token['LinOtp.TokenSerialnumber'])
