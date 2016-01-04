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
""" user authentication with repoze module """

import logging
log = logging.getLogger(__name__)

from linotp.lib.user import getRealmBox, getSplitAtSign
from linotp.lib.realm import getDefaultRealm
from linotp.lib.selftest import isSelfTest
from linotp.lib.util import str2unicode

import traceback

from linotp.lib.user import get_authenticated_user


class UserModelPlugin(object):

    def authenticate(self, environ, identity):
        log.info("[authenticate] entering repoze authenticate function.")
        # log.debug( identity )
        username = None
        realm = None
        options = {}
        realmbox = "False"

        authenticate = True
        if isSelfTest():
            authenticate = False

        try:
            if isSelfTest():
                if ('login' not in identity
                    and 'repoze.who.plugins.auth_tkt.userid' in identity):
                    u = identity.get('repoze.who.plugins.auth_tkt.userid')
                    identity['login'] = u
                    identity['password'] = u

            username = identity['login']
            realm = identity['realm']
            password = identity['password']
            options.update(identity)
            realmbox = options.get("realmbox", "False")

        except KeyError as e:
            log.exception("[authenticate] Keyerror in identity: %r." % e)
            return None

        # convert string to boolean
        realm_mbox = False
        if realmbox.lower() == 'true':
            realm_mbox = True

        # check username/realm, password
        user = get_authenticated_user(username, realm, password,
                                          realm_box=realm_mbox,
                                          authenticate=authenticate,
                                          options=options)
        if not user:
            return None

        authUser = "%s@%s" % (user.login, user.realm)
        return authUser

    def add_metadata(self, environ, identity):
        # username = identity.get('repoze.who.userid')
        # user = User.get(username)
        # user = "clerk maxwell"
        # log.info( "add_metadata: %s" % identity )

        # pp = pprint.PrettyPrinter(indent=4)
        # log.info("add_meta: environ %s" % pp.pformat(environ)
        log.debug("[add_metadata] add some metatata")
        # for k in environ.keys():
        #    log.debug("add_metadata: environ[%s]: %s" % ( k, environ[k] ))

        for k in identity.keys():
            log.debug("[add_metadata] identity[%s]: %s" % (k, identity[k]))

        # if identity.has_key('realm'):
        #    identity.update( { 'realm' : identity['realm'] } )
        #    log.info("add_metadata: added realm: %s" % identity['realm'] )

        return identity
