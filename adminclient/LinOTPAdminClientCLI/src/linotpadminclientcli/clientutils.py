#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
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
this module is used for the communication of the python based management clients
                linotpadm.py and glinotpadm.py
"""

import urllib2, httplib, urllib
import re
import random
import sys, os
import ssl
import logging
import logging.handlers
import cookielib

if sys.version_info[0:2] >= (2, 6):
    import json
else:
    import simplejson as json
import gettext

_ = gettext.gettext

TIMEOUT = 5


file_opts = ['rf_file=']
ldap_opts = ['rl_uri=', 'rl_basedn=', 'rl_binddn=',
    'rl_bindpw=', 'rl_timeout=', 'rl_loginattr=',
    'rl_searchfilter=', 'rl_userfilter=',
    'rl_attrmap=']
ldap_opts_map = { 'rl_uri' : 'LDAPURI',
                'rl_basedn' : 'LDAPBASE',
                'rl_binddn' : 'BINDDN',
                'rl_bindpw' : 'BINDPW',
                'rl_timeout': 'TIMEOUT',
                'rl_searchfilter' : 'LDAPSEARCHFILTER',
                'rl_userfilter' : 'LDAPFILTER',
                'rl_attrmap' : 'USERINFO',
                'rl_loginattr' : 'LOGINNAMEATTRIBUTE'
                }

class LinOTPClientError(Exception):
    '''
    This class is used to throw client exceptions.
    '''
    def __init__(self, id=10, description="LinOTPClientError"):
        self.id = id
        self.description = description
    def getId(self):
        return self.id
    def getDescription(self):
        return self.description
    def __str__(self):
        ## here we lookup the error id - to translate
        return repr("ERR" + str(self.id) + ": " + self.description)



class pyToken:
    '''
    This class is used to generate a pyToken, which is a python based soft-token.
    '''
    def __init__(self, keylen=256, template="pytoken.template.py"):
        self.keylen = keylen
        self.template = template
        self.serial = hex(random.getrandbits(8 * 4))
        self.serial = "pT" + self.serial[2:-1]
        self.hmackey = hex(random.getrandbits(self.keylen))
        self.hmackey = self.hmackey[2:-1]

    def getSerial(self):
        return self.serial

    def getHMAC(self):
        return self.hmackey

    def createToken(self, user):
        # read replace and dump
        f = open (self.template)
        tfile = f.readlines()
        f.close
        usertoken = ""
        for line in tfile:
            p = re.compile('<put_your_hmac_here>')
            mt = p.search(line)
            if mt:
                line = p.sub(self.hmackey, line)
            usertoken = usertoken + line
        return usertoken

class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    '''
    This Class is used to do the client cert auth with urllib2
    found at:
    http://www.osmonov.com/2009/04/client-certificates-with-urllib2.html
    '''
    def __init__(self, key, cert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        '''
        Rather than pass in a reference to a connection class, we pass in
        a reference to a function which, for all intents and purposes,
        will behave as a constructor
        '''
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        return httplib.HTTPSConnection(host, key_file=self.key, cert_file=self.cert)

class linotpclient(object):
    '''
    class linotpclient: This class is created to hold a connection to the LinOTP server
    '''
    def __init__(self, protocol, url, admin=None, adminpw=None,
                cert=None, key=None, disable_ssl_certificate_validation=False,
                proxy=None, authtype="Digest"):
        '''
        arguments:
            The class is created with the parameters
                protocol:   either http or https
                url:        the url of the LinOTP server. It consists of
                            the hostname and the port like:
                            localhost:443
            Optional parameters:
                admin:      If the LinOTP server is configured to use digest auth,
                adminpw:    these are the credentials to authenticate to the
                            LinOTP server
                cert:       If the LinOTP server is configured to use client
                key:        certificate authentication, these are the filenames
                            of the files holding the certificate and the key.

        description:
            At the moment you can either authenticate via digest auth or
            via client certificates. It is not possible to combine the two
            authentication methods.
        '''
        self.protocol = protocol
        self.url = url
        self.admin = admin
        self.adminpw = adminpw
        self.cert = cert
        self.key = key
        self.disable_ssl_certificate_validation = disable_ssl_certificate_validation
        self.proxy = proxy
        self.logging = False
        self.authtype = authtype
        self.log = logging.getLogger('linotpclient')
        self.cookie_jar = cookielib.CookieJar()
        self.session = ""
        if (self.admin and self.adminpw) or (self.cert and self.key):
            self.getsession()

    def setLogging(self, logtoggle=False, param={}):
        self.logging = logtoggle
        self.LOG_FILENAME = param['LOG_FILENAME']
        self.LOG_COUNT = param['LOG_COUNT']
        self.LOG_SIZE = param['LOG_SIZE']
        self.LOG_LEVEL = param['LOG_LEVEL']
        if self.logging:
            self.log.setLevel(self.LOG_LEVEL)
            if hasattr(self, "handler"):
                self.log.removeHandler(self.handler)
            self.handler = logging.handlers.RotatingFileHandler(
                self.LOG_FILENAME, maxBytes=self.LOG_SIZE, backupCount=self.LOG_COUNT)
            self.formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s]:%(message)s")
            self.handler.setFormatter(self.formatter)
            self.log.addHandler(self.handler)
            self.log.debug("Logging initialized")
        else:
            self.log.debug("Logging disabled")
            if hasattr(self, "handler"):
                self.log.removeHandler(self.handler)


    def setcredentials(self, protocol, url, admin=None, adminpw=None,
            cert=None, key=None, proxy=None,
            authtype="Digest", disable_ssl_certificate_validation=False):
        '''
        arguments:
            The same arguments as when initializing the instance.

        description:
            This method can be used, when i.e. the authentication credentials need
            to be changed. If the admin tried to authenticate with username /password
            and he mistyped the password, this function can be used, to reset the
            credentials.
        '''
        self.protocol = protocol
        self.url = url
        self.admin = admin
        self.adminpw = adminpw
        self.cert = cert
        self.key = key
        self.proxy = proxy
        self.authtype = authtype
        self.disable_ssl_certificate_validation = disable_ssl_certificate_validation
        self.getsession()
        if self.logging:
            self.log.info("[setcredentials]: Credentials set successfully.")


    def connect(self, path, param, data={}, json_format=True):
        '''
        arguments:
            path:
                The path argument takes the controller path/method. This can be
                /admin/show
                /admin/init
                /admin/...
                /validate/check
                /validate/simplecheck
                /system/...

            param:
                The param is a dictionary of the parameters, that need to be
                passed to the LinOTP server controller for the specified method.

            data:
                The data, that would be passed in a POST request.
                As soon as the parameter data is provided, we'll do a POST request.

        returns:
            Returns the JSON result as a dictionary.

        exceptions:
            In case of connection errors it raises a
            LinOTPClientError exception.
        '''
        p = urllib.urlencode(param)
        d = ""
        if len(data) > 0:
            # We got data, so we will do a POST request.
            d = urllib.urlencode(data)
        else:
            # We do a normal GET request
            d = ""
        if self.logging:
            self.log.debug("[connect]: data=" + d)
            self.log.debug("[connect]: type of data: %s" % type(d))
            self.log.info ("[connect]: path=" + path)
            self.log.debug("[connect]: param=" + p)

        try:
            auth_handler = None
            if self.admin:
                #########################################################
                #
                # PASSWORD AUTH
                #
                # we got a username, so we will do digest auth
                if not self.adminpw:
                    raise LinOTPClientError(1004, _("When specifying an admin user to authenticate you also need to pass a password."))
                pw_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
                pw_manager.add_password(None, uri=self.protocol + '://' + self.url, user=self.admin, passwd=self.adminpw)

                if "Digest" == self.authtype:
                    # Digest Auth
                    auth_handler = urllib2.HTTPDigestAuthHandler(pw_manager)
                else:
                    # Basic Auth
                    auth_handler = urllib2.HTTPBasicAuthHandler(pw_manager)
            elif (self.cert and (self.protocol == "https")):
                #########################################################
                # CLIENT CERT AUTH
                # We got a certificate, so we will do client cert auth
                auth_handler = HTTPSClientAuthHandler(self.key, self.cert)
        except Exception as  e:
            if self.logging:
                self.log.error("[connect]: Error creating auth handler: %s" % str(e))
            raise LinOTPClientError(1006, _("Error creating auth handler: %s" % str(e)))

        if None == auth_handler:
            if self.logging:
                self.log.error("[connect] No authentication method found!")
            raise LinOTPClientError(1005, "You either need to login or provide a valid client certificate.")

        try:
            # Proxy handler:
            proxy_handler = urllib2.ProxyHandler({})
            proxy_auth_handler = urllib2.ProxyBasicAuthHandler()
            if self.proxy:
                proxy_handler = urllib2.ProxyHandler({self.protocol: self.protocol + '://' + self.proxy + '/'})
                # TODO: Proxy Authentication
                # proxy_auth_handler.add_password(None, self.protocol+'://'+self.url, self.proxyuser, self.proxypass)

            cookie_handler = urllib2.HTTPCookieProcessor(self.cookie_jar)

            ctx = None
            https_handler = urllib2.HTTPSHandler()
            if self.disable_ssl_certificate_validation:
                # only the urlib2 in python 2.7 has the ssl.create_default
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    https_handler = urllib2.HTTPSHandler(context=ctx)
                except AttributeError as exx:
                    # so we have the old ulrlib, which does no verification
                    https_handler = urllib2.HTTPSHandler()

            opener = urllib2.build_opener(https_handler,
                                          auth_handler, proxy_handler,
                                          cookie_handler)

            # ...and install it globally so it can be used with urlopen.
            urllib2.install_opener(opener)

            req_params = {}
            if param:
                req_params.update(param)
            if data:
                req_params.update(data)

            if self.session:
                req_params['session'] = self.session

            p = None
            if req_params:
                p = urllib.urlencode(req_params)

            req_url = self.protocol + '://' + self.url + path
            f = urllib2.urlopen(urllib2.Request(req_url, p))

        except Exception as e:
            if self.logging:
                self.log.error("[connect]: Error connecting to LinOTPd service: %s" % str(e))
            raise LinOTPClientError(1006, _("Error connecting to LinOTPd service: %s" % str(e)))

        # Now evaluate the response.
        if not json_format:
            rv = f.read()
        else:
            status = False
            try:
                rv = json.load(f)
                if rv.get("result"):
                    # in case of normal json output
                    status = rv['result']['status']
                elif rv.get("rows"):
                    # in case of flexigrid output
                    # like with /audit/search
                    status = True
            except:
                if self.logging:
                    self.log.error("[connect]: Internal JSON error. Could not interpret the LinOTP server response: %s" % f)
                raise LinOTPClientError(1003, _("Internal JSON error. Could not interpret the LinOTP server response:  %s") % f)

            if status == False:
                if self.logging:
                    self.log.error("[connect]: Your request to the LinOTP server was invalid: " + rv['result']['error']['message'])
                raise LinOTPClientError(rv['result']['error']['code'], _("Your request to the LinOTP server was invalid: ") + rv['result']['error']['message'])

        return rv


    def command(self, command, param):
        '''
        This is just a mapper method to map a command to a path, i.e
        a pylons controller/method of the LinOTP server

        arguments:
            command: can be something like:
                    userlist
                    inittoken
                    listtoken
                    assigntoken
                    unassigntoken
                    resetfailcounter
                    resynctoken
                    set
                    setscpin
                    setmaxfail


        '''
        #return self.connect(self.commandmap[command], param)

    def getsession(self):
        self.connect("/admin/getsession", {}, {})
        for cookie in self.cookie_jar:
            if cookie.name == "admin_session":
                self.session = cookie.value
        return self.session

    def userlist(self, param):
        return self.connect('/admin/userlist', param)

    def auditsearch(self, param):
        return self.connect('/audit/search', param)

    def inittoken(self, param):
        return self.connect('/admin/init', param)

    def listtoken(self, param):
        return self.connect('/admin/show', param)

    def getserialbyotp(self, param):
        return self.connect('/admin/getSerialByOtp', param)

    def copytokenpin(self, param):
        return self.connect('/admin/copyTokenPin', param)

    def assigntoken(self, param):
        return self.connect('/admin/assign', param)

    def unassigntoken (self, param):
        return self.connect('/admin/unassign', param)

    def resetfailcounter(self, param):
        return self.connect('/admin/reset', param)

    def resynctoken(self, param):
        return self.connect('/admin/resync', param)

    def tokenrealm(self, serial, realms):
        return self.connect('/admin/tokenrealm', { 'serial':serial, 'realms':realms})

    def set(self, param):
        '''
        This function is used for many purposes like
            setmaxfail
            setsyncwindow
            setotplen
        This depends on the contents of the param dictionary.
        '''
        return self.connect('/admin/set', param)

    def get_policy(self, param={}):
        return self.connect('/system/getPolicy', param)

    def setscpin(self, param):
        return self.connect('/admin/setPin', param)

    def disabletoken(self, param):
        param['enable'] = 'False'
        return self.connect('/admin/disable', param)

    def enabletoken(self, param):
        param['enable'] = 'True'
        return self.connect('/admin/enable', param)

    def removetoken (self, param):
        return self.connect('/admin/remove', param)

    def readserverconfig(self, param):
        return self.connect('/system/getConfig', param)

    def writeserverconfig(self, param):
        return self.connect('/system/setConfig', param)

    def getrealms(self, param):
        return self.connect('/system/getRealms', param)

    def securitymodule(self, param={}):
        return self.connect('/system/setupSecurityModule', param)

    def setrealm(self, param):
        return self.connect('/system/setRealm', param)

    def deleterealm(self, param):
        return self.connect('/system/delRealm', param)

    def setdefaultrealm(self, param):
        return self.connect('/system/setDefaultRealm', param)

    def deleteconfig(self, param):
        return self.connect('/system/delConfig', param)

    def setresolver(self, param):
        if (not 'resolver' in param):
            raise LinOTPClientError(1201, _("When setting a resolver, you need to specify 'resolver'."))

        if param['rtype'] == 'FILE':
            if (not 'rf_file' in param):
                raise LinOTPClientError(1201, _("When setting a flat file resolver, you need to specify 'rf_file'."))
            r1 = self.writeserverconfig({ 'passwdresolver.fileName.' + param['resolver'] : param['rf_file'] })
            return r1

        elif param['rtype'] == 'LDAP':
            for k, v in ldap_opts_map.items():
                if not k in param:
                    raise LinOTPClientError(1201, _("When setting an ldap resolver, you need to specify '%s'.") % k)
                r1 = self.writeserverconfig({ 'ldapresolver.' + v + '.' + param['resolver']: param[ k ] })
            return r1
        elif param['rtype'] == 'SQL':
            print "TODO: Doing the Voodoo to set all these config keys"

        return {}

    def deleteresolver(self, param):
        r1 = self.readserverconfig({})
        for (k, v) in r1['result']['value'].items():
            resolver = k.split(".")
            if len(resolver) == 3:
                if resolver[0] in ("passwdresolver", "ldapresolver", "sqlresolver"):
                    if resolver[2] == param['resolver']:
                        print "deleting config key %s." % k
                        self.deleteconfig({'key':k })


    def getresolvers(self, param):
        r1 = self.readserverconfig(param)
        # now we need to split all the resolving stuff.
        newResolver = {}
        for (k, v) in r1['result']['value'].items():
            resolver = k.split(".")
            if len(resolver) == 3:
                if resolver[0]in ("passwdresolver", "ldapresolver", "sqlresolver"):
                    if newResolver.has_key(resolver[2]) == False:
                        newResolver[resolver[2]] = {}
                    newResolver[resolver[2]]['type'] = resolver[0]
                    newResolver[resolver[2]][resolver[1]] = v
        r2 = { 'result' : { 'value' : newResolver } }
        return r2


    def importtoken(self, param):
        if not param['file']:
            print "Please specify a filename to import the token from"
            return False
        f = open (param['file'])
        tokenfile = f.readlines()
        f.close
        tokenserial = ""
        tokenseed = ""
        tokens = 0
        token_count = 0
        for line in tokenfile:
            mt = re.search('<Token serial=\"(.*)\">', line)
            if mt:
                token_count = token_count + 1
        for line in tokenfile:
            # Format like
            #<Token serial="F800574">
            #<Seed>F71E5AC721B7353735F52494E61B1A62538A0238</Seed>
            mt = re.search('<Token serial=\"(.*)\">', line)
            if mt:
                if tokenseed:
                    print "Error: Got a seed (" + tokenseed + ")without a serial!"
                else:
                    tokenserial = mt.group(1)
                    tokens = tokens + 1
                    print "Importing token", tokens, "/", token_count, "with serial", tokenserial
            else:
                ms = re.search('<Seed>(.*)</Seed>', line)
                if ms:
                    tokenseed = ms.group(1)
                    if tokenserial:
                        ret = self.inittoken({ 'serial':tokenserial, 'otpkey':tokenseed, 'description':"Safeword", 'user':'', 'pin':''})
                        if ret['result']['status'] == False:
                            print ret['result']['error']['message']
                        tokenseed = ""
                        tokenserial = ""
                    else:
                        print "Error: Got a seed (" + tokenseed + ") without a serial!"
        print "%i tokens imported." % tokens
        return True


def dumpresult(status, data, tabformat):
    '''
    This function is used to print the Tokenlist in a nice viewable
    ascii table.
    '''
    tabsize = tabformat['tabsize']
    tabstr = tabformat['tabstr']
    tabdelim = tabformat['tabdelim']
    tabvisible = tabformat['tabvisible']
    tabhead = tabformat['tabhead']
    tabentry = tabformat['tabentry']

    #if not result['status']:
    if not status:
        print "The return status is false"
    else:

        head = tabentry

        # Set the default, if no tabformat or a wrong tabformat is passed
        if not len(tabvisible):
            for i in range(0, len(head)):
                tabvisible.append(i)
        if len(tabhead) < len(head):
            print "tabhead " + str(len(tabhead)) + " head " + str(len(head))
            for i in range(0, len(head)):
                tabhead.append('head')
        if len(tabsize) < len(head):
            for i in range(0, len(head)):
                tabsize.append(10)
        if len(tabstr) < len(head):
            for i in range(0, len(head)):
                tabstr.append("%10s")

        #value = result['value']
        #data = value['data']

        i = 0
        for t in tabhead:
            print tabstr[i] % str(t) [:tabsize[i]], tabdelim,
            i = i + 1
        print

        for token in data:
            i = 0
            for t in tabentry:
                #print tabstr[i] % str(token.get(t)).endcode('utf-8') [:tabsize[i]], tabdelim,
                #text=str(token.get(t)).encode('utf-8')
                text = token.get(t)
                if not type(token.get(t)) == unicode:
                    text = str(token.get(t))
                # If we got a IdResClass like useridresolver.PasswdIdResolver.IdResolver.pw2
                # we only want to get the last field
                if t == "LinOtp.IdResClass":
                    r = text.split('.')
                    if len(r) == 4:
                        text = r[3]
                print tabstr[i] % text [:tabsize[i]], tabdelim,
                i = i + 1
            print
