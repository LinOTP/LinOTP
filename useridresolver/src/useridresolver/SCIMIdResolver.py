# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP userid resolvers.
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
""" This module implements the communication interface
                for resolving user information from a SCIM service

    status is experimental
"""

import logging
log = logging.getLogger(__name__)

from UserIdResolver import UserIdResolver
from UserIdResolver import getResolverClass

try:
    from osiam import connector
    from requests.auth import HTTPBasicAuth
    import requests
except Exception as ex:
    log.warn("Missing modules for SCIMResolver: %r" % str(ex))
    raise ex

import json


class IdResolver (UserIdResolver):

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        '''
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        '''
        log.info("Setting up the SCIMResolver")
        return

    def close(self):
        return

    def check_scim(self):
        if self.scim is None:
            raise Exception("SCIMResolver has no scim object set. You need to call the loadconfig before calling user functions.")

    def __init__(self):
        self.name = "scim-default"
        self.auth_server = ''
        self.resource_server = ''
        self.auth_client = 'localhost'
        self.auth_secret = ''
        self.scim = None

    def get_access_token(self, server=None, client=None, secret=None):
        res = requests.post('%s/oauth/token' % self.auth_server,
                          auth=HTTPBasicAuth(client, secret),
                          params={'grant_type': 'client_credentials',
                                  'scope' : 'GET POST'},
                          verify=False)
        access_token = res.json().get('access_token')
        log.debug("Access Token: %r" % access_token)
        return access_token

    def create_scim_object(self):
        access_token = self.get_access_token(self.auth_server, self.auth_client, self.auth_secret)
        self.scim = connector.SCIM(self.resource_server, access_token)
        return


    def checkPass(self, uid, password):
        """
        This function checks the password for a given uid.
        - returns true in case of success
        -         false if password does not match

        TODO
        """
        return False

    def getUserInfo(self, userId):
        '''
        returns the user information for a given uid.
        '''
        ret = {}
        self.check_scim()
        res = self.scim.search_with_get_on_users('filter=%s eq %s' % (self.mapping.get("userid"),
                                                                        userId))
        user = res.get("Resources", [{}])[0]

        ret['username'] = user.get(self.mapping.get("username"))
        ret['givenname'] = user.get(self.mapping.get("givenname"), "")
        ret['surname'] = user.get(self.mapping.get("surname"), "")
        ret['phone'] = user.get(self.mapping.get("phone"), "")
        ret['mobile'] = user.get(self.mapping.get("mobile"), "")
        ret['email'] = user.get(self.mapping.get("email"), "")

        return ret

    def getUsername(self, userId):
        '''
        returns the loginname for a given userId
        '''
        user = self.getUserInfo(userId)
        return user.get("username")


    def getUserId(self, LoginName):
        """
        returns the uid for a given loginname/username
        """
        self.check_scim()
        res = self.scim.search_with_get_on_users('filter=%s eq %s' % (self.mapping.get("username"),
                                                                        LoginName))
        return res.get("Resources", [{}])[0].get(self.mapping.get("userid"))

    def getUserList(self, searchDict):
        '''
        Return the list of users
        '''
        ret = []

        '''
        TODO: search dict
        '''
        self.check_scim()
        res = self.scim.search_with_get_on_users("")

        for user in res.get("Resources"):
            ret_user = {}
            ret_user['username'] = user.get(self.mapping.get("username"))
            ret_user['userid'] = user.get(self.mapping.get("userid"))
            ret_user['surname'] = user.get(self.mapping.get("surname"), "")
            ret_user['givenname'] = user.get(self.mapping.get("givenname"), "")
            ret_user['email'] = user.get(self.mapping.get("email"), "")
            ret_user['phone'] = user.get(self.mapping.get("phone"), "")
            ret_user['mobile'] = user.get(self.mapping.get("mobile"), "")

            ret.append(ret_user)

        return ret



#############################################################
# server inf methods
#############################################################
    def getResolverId(self):
        """ getResolverId(LoginName)
            - returns the resolver identifier string
            - empty string if not exist
        """
        return self.name

    def getResolverType(self):
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassType(cls):
        return 'scimresolver'

    @classmethod
    def getResolverClassDescriptor(cls):
        '''
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        '''
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.SCIMIdResolver.IdResolver"
        descriptor['config'] = {'authserver' : 'string',
                                'resourceserver' : 'string',
                                'authclient' : 'string',
                                'authsecret' : 'string',
                                'mapping' : 'string' }
        return {typ : descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def getConfigEntry(self, config, key, conf, required=True):
        ckey = key
        cval = ""
        if conf != "" or None:
            ckey = ckey + "." + conf
            if ckey in config:
                cval = config[ckey]
        if cval == "":
            if key in config:
                cval = config[key]
        if cval == "" and required == True:
            raise Exception("missing config entry: " + key)
        return cval

    def loadConfig(self, config, conf):
        """ loadConfig(configDict)
            The UserIdResolver could be configured
            from the pylon app config
        """
        self.name = conf
        self.auth_server = self.getConfigEntry(config, 'linotp.scimresolver.authserver', conf)
        self.resource_server = self.getConfigEntry(config, 'linotp.scimresolver.resourceserver', conf)
        self.auth_client = self.getConfigEntry(config, 'linotp.scimresolver.client', conf)
        self.auth_secret = self.getConfigEntry(config, 'linotp.scimresolver.secret', conf)
        self.mapping = json.loads(self.getConfigEntry(config, 'linotp.scimresolver.mapping', conf))
        self.create_scim_object()

        return





if __name__ == "__main__":

    print " SCIMIdResolver - IdResolver class test "

    y = getResolverClass("SCIMIdResolver", "IdResolver")()

    y.loadConfig({ 'linotp.scimresolver.authserver' : 'http://osiam:8080/osiam-auth-server',
                  'linotp.scimresolver.resourceserver' : 'http://osiam:8080/osiam-resource-server',
                   'linotp.scimresolver.secret' : '40e919e3-0834-447a-b39c-d14329c99941',
                   'linotp.scimresolver.client' : 'puckel',
                   'linotp.scimresolver.mapping' : '{ "username" : "userName" , "userid" : "id"}'}, "")

    print "==== the complete userlist ======="
    print y.getUserList({})
    print "=================================="

    user = "marissa"
    loginId = y.getUserId(user)

    print " %s -  %s" % (user , loginId)
    print " reId - " + y.getResolverId()

    ret = y.getUserInfo(loginId)


    print ret

