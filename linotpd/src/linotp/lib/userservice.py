# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
""" logic for the userservice processing """

import binascii
import os
import datetime
import hmac
import hashlib
import base64
import json

# for the temporary rendering context, we use 'c'
from pylons import (tmpl_context as c
                    )

from pylons.templating import render_mako as render


from linotp.lib.policy import (get_client_policy,
                               getSelfserviceActions,
                               )


from linotp.lib.util import (get_version,
                             get_copyright_info,
                             get_request_param)

from linotp.lib.type_utils import parse_duration

from linotp.lib.realm import getRealms

from linotp.lib.selfservice import get_imprint

from linotp.lib.user import (
                              getRealmBox,
                             )

from linotp.lib.token import getTokens4UserOrSerial
from linotp.lib.token import get_token_owner

from linotp.tokens import tokenclass_registry

from linotp.lib.user import (getUserInfo,
                             User,
                             getUserId)

from linotp.lib.realm import getDefaultRealm
from linotp.lib.context import request_context

from linotp.lib.type_utils import DEFAULT_TIMEFORMAT as TIMEFORMAT

import logging
log = logging.getLogger(__name__)

# const for encryption and iv
SECRET_LEN = 32



Cookie_Secret = binascii.hexlify(os.urandom(SECRET_LEN))
Cookie_Cache = {}


def get_userinfo(user):

    (uid, resolver, resolver_class) = getUserId(user)
    uinfo = getUserInfo(uid, resolver, resolver_class)
    if 'cryptpass' in uinfo:
        del uinfo['cryptpass']

    return uinfo


def getTokenForUser(user, active=None, exclude_rollout=True):
    """
    should be moved to token.py
    """
    tokenArray = []

    log.debug("[getTokenForUser] iterating tokens for user...")
    log.debug("[getTokenForUser] ...user %s in realm %s.",
              user.login, user.realm)

    tokens = getTokens4UserOrSerial(user=user, serial=None, _class=True,
                                    active=active)

    for token in tokens:

        tok = token.token.get_vars()
        if tok.get('LinOtp.TokenInfo', None):
            token_info = json.loads(tok.get('LinOtp.TokenInfo'))

            # skip the rollout tokens from the selfservice token list

            path = token_info.get('scope',{}).get('path',[])
            if set(path) & set(['userservice', 'validate']) and exclude_rollout:
                continue

            tok['LinOtp.TokenInfo'] = token_info

        tok['Enrollment'] = token.get_enrollment_status()

        tokenArray.append(tok)

    log.debug("[getTokenForUser] found tokenarray: %r" % tokenArray)
    return tokenArray


def _get_realms_():
    realms = {}
    if getRealmBox():
        realms = getRealms()
    else:
        def_realm = getDefaultRealm()
        if getDefaultRealm():
            realms = getRealms(def_realm)
    return realms


def create_auth_cookie(user, client, state='authenticated', state_data=None):
    """
    create and auth_cookie value from the authenticated user and client

    :param user: the authenticated user
    :param client: the requesting client
    :param state: the state info for the authentication
    :return: the hmac256digest of the user data
             the expiration time as datetime
             the expiration time as string
    """

    secret = get_cookie_secret()
    key = binascii.unhexlify(secret)

    # ---------------------------------------------------------------------- --

    # handle expiration calculation

    expiry = get_cookie_expiry()

    if expiry is False:
        # default should be at max 1 hour
        delta = datetime.timedelta(seconds=1 * 60 * 60)
    else:
        delta = parse_duration(expiry)

    now = datetime.datetime.utcnow()
    expires = now + delta
    expiration = expires.strftime(TIMEFORMAT)

    # ---------------------------------------------------------------------- --

    # build the cache data

    data = [user, client, expiration, state, state_data]

    digest = hmac.new(key, "%r" % data, digestmod=hashlib.sha256).digest()
    auth_cookie = base64.urlsafe_b64encode(digest).decode().strip("=")

    Cookie_Cache[auth_cookie] = data

    return auth_cookie, expires, expiration


def get_cookie_authinfo(cookie):
    """
    return the authentication data from the cookie, which is the user
    and the auth state and the optional state_data

    :param cookie: the session cookie, which is an hmac256 hash
    :return: triple of user, state and state_data
    """

    data = Cookie_Cache.get(cookie)

    if not data:
        return None, None, None, None

    [user, client, expiration, state, state_data] = data

    # handle session expiration

    now = datetime.datetime.utcnow()
    expires = datetime.datetime.strptime(expiration, TIMEFORMAT)
    if now > expires:
        log.info("session is expired")
        return None, None, None, None

    return user, client, state, state_data


def remove_auth_cookie(cookie):
    """
    verify that value of the auth_cookie contains the correct user and client

    :param user: the authenticated user object
    :param cookie: the auth_cookie
    :param client: the requesting client

    :return: boolean
    """

    if cookie in Cookie_Cache:
        del Cookie_Cache[cookie]


def check_auth_cookie(cookie, user, client):
    """
    verify that value of the auth_cookie contains the correct user and client

    :param user: the authenticated user object
    :param cookie: the auth_cookie
    :param client: the requesting client

    :return: boolean
    """

    data = Cookie_Cache.get(cookie)

    if not data:
        return False

    [cookie_user, cookie_client, expiration, _state, _state_data] = data

    # handle session expiration

    now = datetime.datetime.utcnow()
    expires = datetime.datetime.strptime(expiration, TIMEFORMAT)

    if now > expires:
        log.info("session is expired")
        return False

    if client is None and not cookie_client:
        cookie_client = None

    return (user == cookie_user and cookie_client == client)


def get_cookie_secret():
    """
    get the cookie encryption secret from the config
    - if the selfservice is droped from running localy, this
      configuration option might not exist anymore

    :return: return the cookie encryption secret
    """
    return Cookie_Secret


def get_cookie_expiry():
    """
    get the cookie encryption expiry from the config
    - if the selfservice is dropped from running locally, this
      configuration option might not exist anymore

    :return: return the cookie encryption expiry
    """
    config = request_context['Config']

    return config.get('selfservice.auth_expiry', False)


def check_session(request, user, client):
    """
    check if the user session is ok:
    - check if the sessionvalue is the same as the cookie
    - check if the user has been authenticated before by decrypt the cookie val

    :param request: the request context
    :param user:the authenticated user
    :param client: the cookie is bouind to the client

    :return: boolean
    """

    # try to get (local) selfservice
    # if none is present fall back to possible
    # userauthcookie (cookie for remote self service)

    session = get_request_param(request, 'session', 'no_session')

    for cookie_ref in ['user_selfservice', 'userauthcookie']:

        cookie = request.cookies.get(cookie_ref, 'no_auth_cookie')

        if session == cookie:
            return check_auth_cookie(cookie, user, client)

    return False


def get_pre_context(client):
    """
    get the rendering context before the login is shown, so the rendering
    of the login page could be controlled if realm_box or mfa_login is
    defined

    :param client: the rendering is client dependend, so we need the info
    :return: context dict, with all rendering attributes
    """

    pre_context = {}
    pre_context["version"] = get_version()
    pre_context["licenseinfo"] = get_copyright_info()

    pre_context["default_realm"] = getDefaultRealm()
    pre_context["realm_box"] = getRealmBox()

    pre_context["realms"] = json.dumps(_get_realms_())

    # check for mfa_login, autoassign and autoenroll in policy definition

    pre_context['mfa_login'] = False
    policy = get_client_policy(client=client,
                               scope='selfservice',
                               action='mfa_login')
    if policy:
        pre_context['mfa_login'] = True

    pre_context['mfa_3_fields'] = False
    policy = get_client_policy(client=client,
                               scope='selfservice',
                               action='mfa_3_fields')
    if policy:
        pre_context['mfa_3_fields'] = True

    pre_context['autoassign'] = False
    policy = get_client_policy(client=client,
                               scope='enrollment',
                               action='autoassignment')
    if policy:
        pre_context['autoassign'] = True

    pre_context['autoenroll'] = False
    policy = get_client_policy(client=client,
                               scope='enrollment',
                               action='autoenrollment')
    if policy:
        pre_context['autoenroll'] = True

    return pre_context


def get_context(config, user, realm, client):
    """
    get the user dependend rendering context

    :param user: the selfservice user
    :param realm: the selfservice realm
    :param client: the selfservice client info - required for pre_context
    :return: context dict, with all rendering attributes

    """

    req_context = get_pre_context(client)

    req_context["user"] = user
    req_context["realm"] = realm
    authUser = User(user, realm)
    req_context["imprint"] = get_imprint(req_context["realm"])
    req_context["tokenArray"] = getTokenForUser(authUser)

    # show the defined actions, which have a rendering
    actions = getSelfserviceActions(authUser)
    req_context["actions"] = actions
    for policy in actions:
        if "=" in policy:
            (name, val) = policy.split('=')
            val = val.strip()
            # try if val is a simple numeric -
            # w.r.t. javascript evaluation
            try:
                nval = int(val)
            except:
                nval = val
            req_context[name.strip()] = nval

    req_context["dynamic_actions"] = add_dynamic_selfservice_enrollment(config, actions)

    # TODO: to establish all token local defined policies
    additional_policies = add_dynamic_selfservice_policies(config, actions)
    for policy in additional_policies:
        req_context[policy] = -1

    # TODO: add_local_policies() currently not implemented!!
    req_context["otplen"] = -1
    req_context["totp_len"] = -1

    return req_context


##############################################################################

def add_dynamic_selfservice_enrollment(config, actions):
    '''
        add_dynamic_actions - load the html of the dynamic tokens
            according to the policy definition

        :param actions: the allowd policy actions for the current scope
        :type  actions: array of actions names

        :return: hash of {tokentype : html for tab}
    '''

    dynanmic_actions = {}

    for tclass_object in set(tokenclass_registry.values()):
        tok = tclass_object.getClassType()
        if hasattr(tclass_object, 'getClassInfo'):

            try:
                selfservice = tclass_object.getClassInfo('selfservice', ret=None)
                # # check if we have a policy in the token definition for the enroll
                if selfservice.has_key('enroll') and 'enroll' + tok.upper() in actions:
                    service = selfservice.get('enroll')
                    tab = service.get('title')
                    c.scope = tab.get('scope')
                    t_file = tab.get('html')
                    t_html = render(t_file)
                    ''' remove empty lines '''
                    t_html = '\n'.join([line for line in t_html.split('\n') if line.strip() != ''])
                    e_name = "%s.%s.%s" % (tok, 'selfservice', 'enroll')
                    dynanmic_actions[e_name] = t_html

                # # check if there are other selfserive policy actions
                policy = tclass_object.getClassInfo('policy', ret=None)
                if 'selfservice' in policy:
                    selfserv_policies = policy.get('selfservice').keys()
                    for action in actions:
                        if action in selfserv_policies:
                            # # now lookup, if there is an additional section
                            # # in the selfservice to render
                            service = selfservice.get(action)
                            tab = service.get('title')
                            c.scope = tab.get('scope')
                            t_file = tab.get('html')
                            t_html = render(t_file)
                            ''' remove empty lines '''
                            t_html = '\n'.join([line for line in t_html.split('\n') if line.strip() != ''])
                            e_name = "%s.%s.%s" % (tok, 'selfservice', action)
                            dynanmic_actions[e_name] = t_html


            except Exception as e:
                log.info('[_add_dynamic_actions] no policy for tokentype '
                         '%s found (%r)' % (unicode(tok), e))

    return dynanmic_actions


def add_dynamic_selfservice_policies(config, actions):
    '''
        add_dynamic_actions - load the html of the dynamic tokens
            according to the policy definition

        :param actions: the allowd policy actions for the current scope
        :type  actions: array of actions names

        :return: hash of {tokentype : html for tab}
    '''

    dynamic_policies = []

    defined_policies = []

    for tok in tokenclass_registry:
        tclt = tokenclass_registry.get(tok)
        if hasattr(tclt, 'getClassInfo'):
            # # check if we have a policy in the token definition
            try:
                policy = tclt.getClassInfo('policy', ret=None)
                if policy is not None and policy.has_key('selfservice'):
                    scope_policies = policy.get('selfservice').keys()
                    ''' initialize the policies '''
                    if len(defined_policies) == 0:
                        for pol in actions:
                            if '=' in pol:
                                (name, val) = pol.split('=')
                                defined_policies.append(name)

                    for local_policy in scope_policies:
                        if local_policy not in defined_policies:
                            dynamic_policies.append(local_policy)
            except Exception as e:
                log.info('[_add_dynamic_actions] no policy for tokentype '
                         '%s found (%r)' % (unicode(tok), e))

    return dynamic_policies

def add_local_policies():

    return

