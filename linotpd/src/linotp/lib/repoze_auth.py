# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
""" user authentication with repoze module """

import logging
log = logging.getLogger(__name__)

from linotp.lib.user import getRealmBox, getSplitAtSign
from linotp.lib.realm import getDefaultRealm
from linotp.lib.resolver import setupResolvers
from linotp.lib.selftest import isSelfTest
from linotp.lib.util import str2unicode
from linotp.lib.context import request_context
from linotp.lib.context import request_context_safety
from linotp.lib.config import getLinotpConfig
from linotp.lib.config import getGlobalObject
from linotp.lib.resolver import initResolvers
from pylons import config

import traceback

from linotp.lib.user import get_authenticated_user


class UserModelPlugin(object):

    def authenticate(self, environ, identity):
        log.debug("Authentication through repoze.")
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
            log.exception("Keyerror in repoze identity: %r." % e)
            return None

        # convert string to boolean
        realm_mbox = False
        if realmbox.lower() == 'true':
            realm_mbox = True

        # check username/realm, password
        with request_context_safety():
            linotp_config = getLinotpConfig()
            request_context['Config'] = linotp_config

            # add the cache manager to the context
            glo = getGlobalObject()
            cache_manager = glo.cache_manager
            request_context['CacheManager'] = cache_manager

            # and also add the hsm - enables us to do otp validation :-)
            sep = glo.security_provider
            hsm = sep.getSecurityModule()
            request_context['hsm'] = hsm

            # initialize the base context
            # - copied for the dumb repoze middleware

            cache_dir = config.get("app_conf", {}).get("cache_dir", None)
            setupResolvers(config=linotp_config, cache_dir=cache_dir)
            resolver_context = initResolvers()
            request_context.update(resolver_context)

            # prepare the request local user cache
            if 'UserLookup' not in request_context:
                request_context['UserLookup'] = {}

            user = get_authenticated_user(username, realm, password,
                                          realm_box=realm_mbox,
                                          authenticate=authenticate,
                                          options=options)

        if not user:
            return None

        authUser = "%s@%s" % (user.login, user.realm)
        return authUser

    def add_metadata(self, environ, identity):
        return identity
