# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
""" user authentication with repoze module """

import logging
log = logging.getLogger(__name__)

import re

from linotp.lib.user import getRealmBox
from linotp.lib.realm import getDefaultRealm
from linotp.lib.selftest import isSelfTest
import traceback

from linotp.lib.user import check_user_password

class UserModelPlugin(object):

    def authenticate(self, environ, identity):
        log.info("[authenticate] entering repoze authenticate function.")
        #log.debug( identity )
        username = None
        realm = None
        success = None
        try:
            if isSelfTest():
                if identity.has_key('login') == False and identity.has_key('repoze.who.plugins.auth_tkt.userid') == True:
                    u = identity.get('repoze.who.plugins.auth_tkt.userid')
                    identity['login'] = u
                    identity['password'] = u

            if getRealmBox():
                username = identity['login']
                realm = identity['realm']
            else:
                log.info("[authenticate] no realmbox, so we are trying to split the loginname")
                m = re.match("(.*)\@(.*)", identity['login'])
                if m:
                    if 2 == len(m.groups()):
                        username = m.groups()[0]
                        realm = m.groups()[1]
                        log.info("[authenticate] found @: username: %r, realm: %r" % (username, realm))
                else:
                    username = identity['login']
                    realm = getDefaultRealm()
                    log.info("[authenticate] using default Realm: username: %r, realm: %r" % (username, realm))

            password = identity['password']
        except KeyError as e:
            log.error("[authenticate] Keyerror in identity: %r." % e)
            log.error("[authenticate] %s" % traceback.format_exc())
            return None

        # check username/realm, password
        if isSelfTest():
            success = "%s@%s" % (unicode(username), unicode(realm))
        else:
            success = check_user_password(username, realm, password)

        return success

    def add_metadata(self, environ, identity):
        #username = identity.get('repoze.who.userid')
        #user = User.get(username)
        #user = "conelius koelbel"
        #log.info( "add_metadata: %s" % identity )

        #pp = pprint.PrettyPrinter(indent=4)
        #log.info("add_meta: environ %s" % pp.pformat(environ)
        log.debug("[add_metadata] add some metatata")
        #for k in environ.keys():
        #    log.debug("add_metadata: environ[%s]: %s" % ( k, environ[k] ))

        for k in identity.keys():
            log.debug("[add_metadata] identity[%s]: %s" % (k, identity[k]))

        #if identity.has_key('realm'):
        #    identity.update( { 'realm' : identity['realm'] } )
        #    log.info("add_metadata: added realm: %s" % identity['realm'] )

        return identity
