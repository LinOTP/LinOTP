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
""" logic for the userservice processing """

import binascii
import os
import datetime

try:
    import json
except ImportError:
    import simplejson as json

# for the temporary rendering context, we use 'c'
from pylons import (tmpl_context as c
                    )

from pylons.templating import render_mako as render


from linotp.lib.policy import (get_client_policy,
                               getSelfserviceActions,
                               )


from linotp.lib.util import (get_version,
                             get_copyright_info,
                             )

from linotp.lib.type_utils import parse_duration

from linotp.lib.realm import getRealms

from linotp.lib.selfservice import get_imprint

from linotp.lib.user import (
                              getRealmBox,
                             )


from linotp.lib.token import (getTokens4UserOrSerial,
                              newToken,
                              )


from linotp.lib.crypto import (aes_decrypt_data,
                              aes_encrypt_data
                              )


from linotp.lib.user import (getUserInfo,
                              User,
                              getUserId)

from linotp.lib.realm import getDefaultRealm




import logging
log = logging.getLogger(__name__)

# const for encryption and iv
SECRET_LEN = 32

# const - timeformat used in session cookie
TIMEFORMAT = "%Y-%m-%d %H:%M:%S"


def get_userinfo(login):

    uinfo = {}

    if '@' in login:
        uuser, rrealm = login.split("@")
        user = User(uuser, rrealm)
    else:
        realm = getDefaultRealm()
        user = User(login, realm)

    (uid, resolver, resolver_class) = getUserId(user)
    uinfo = getUserInfo(uid, resolver, resolver_class)

    # the passwd resolver should not expose the crypted/hasehd password
    if 'cryptpass' in uinfo:
        del uinfo['cryptpass']

    return uinfo

def getTokenForUser(user):
    """
    should be moved to token.py
    """
    tokenArray = []

    log.debug("[getTokenForUser] iterating tokens for user...")
    log.debug("[getTokenForUser] ...user %s in realm %s." % (user.login, user.realm))
    tokens = getTokens4UserOrSerial(user=user, serial=None, _class=False)

    for token in tokens:
        tok = token.get_vars()
        if tok.get('LinOtp.TokneInfo', None):
            token_info = json.loads(tok.get('LinOtp.TokneInfo'))
            tok['LinOtp.TokenInfo'] = token_info
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


def create_auth_cookie(config, user, client):
    """
    create and auth_cookie value from the authenticated user and client

    :param user: the authenticated user
    :param client: the requesting client
    :return: the encrypted cookie value, the expires datetime object and
             the expiration time as string
    """

    secret = get_cookie_secret(config)
    expiry = get_cookie_expiry(config)

    if expiry:
        delta = parse_duration(expiry)
    else:
        # default should be at max 1 hour
        delta = datetime.timedelta(seconds=1 * 60 * 60)

    now = datetime.datetime.now()
    expires = now + delta
    expiration = expires.strftime(TIMEFORMAT)

    key = binascii.unhexlify(secret)

    username = "%r" % user
    if type(user) == User:
        username = "%r@%r" % (user.login, user.realm)
    iv = os.urandom(SECRET_LEN)
    try:
        enc = aes_encrypt_data(username + "|" + client + '|' + expiration,
                               key, iv)
    except Exception as exx:
        log.exception("Failed to create encrypted cookie %r" % exx)
        raise exx

    auth_cookie = "%s%s" % (binascii.hexlify(iv), binascii.hexlify(enc))
    return auth_cookie, expires, expiration


def check_auth_cookie(config, cookie, user, client):
    """
    verify that value of the auth_cookie contains the correct user and client

    :param user: the authenticated user object
    :param cookie: the auth_cookie
    :param client: the requesting client

    :return: boolean
    """
    secret = get_cookie_secret(config)
    key = binascii.unhexlify(secret)

    try:
        iv = cookie[:2 * SECRET_LEN]
        enc = cookie[2 * SECRET_LEN:]
        auth_cookie_val = aes_decrypt_data(binascii.unhexlify(enc),
                                           key,
                                           binascii.unhexlify(iv))
        cookie_user, cookie_client, expiration = auth_cookie_val.split('|')

        # handle session expiration
        now = datetime.datetime.now()
        expires = datetime.datetime.strptime(expiration, TIMEFORMAT)
        if now > expires:
            log.info("session is expired")
            return False

    except Exception as exx:
        log.exception("Failed to decode cookie - session key seems to be old")
        return False

    username = user
    if type(user) == User:
        username = "%r@%r" % (user.login, user.realm)

    return (username == cookie_user and cookie_client == client)


def get_cookie_secret(config):
    """
    get the cookie encryption secret from the repoze config
    - if the selfservice is droped from running localy, this
      configuration option might not exist anymore

    :return: return the cookie encryption secret
    """

    if not config.get('selfservice_auth_secret'):
        secret = binascii.hexlify(os.urandom(SECRET_LEN))
        config['selfservice_auth_secret'] = secret

    return config.get('selfservice_auth_secret')


def get_cookie_expiry(config):
    """
    get the cookie encryption expiry from the repoze config
    - if the selfservice is dropped from running locally, this
      configuration option might not exist anymore

    :return: return the cookie encryption expiry
    """

    return config.get('selfservice.auth_expiry', False)


def check_userservice_session(request, config, user, client):
    """
    check if the user session is ok:
    - check if the sessionvalue is the same as the cookie
    - check if the user has been authenticated before by decrypt the cookie val

    :param request: the request context
    :param user:the authenticated user
    :param client: the cookie is bouind to the client

    :return: boolean
    """
    ret = False

    cookie = request.cookies.get('userauthcookie', 'no_auth_cookie')
    session = request.params.get('session', 'no_session')

    if session == cookie:
        ret = check_auth_cookie(config, cookie, user, client)

    return ret

def get_pre_context(client):
    """
    get the rendering context before the login is shown, so the rendering
    of the login page could be controlled if realm_box or otpLogin is
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


    """
    check for otpLogin, autoassign and autoenroll in policy definition
    """

    pre_context['otpLogin'] = False
    policy = get_client_policy(client=client,
                                scope='selfservice',
                                action='otpLogin')
    if policy:
        pre_context['otpLogin'] = True

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
    g = config['pylons.app_globals']
    tokenclasses = g.tokenclasses

    for tok in tokenclasses.keys():
        tclass = tokenclasses.get(tok)
        tclass_object = newToken(tclass)
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
    g = config['pylons.app_globals']
    tokenclasses = g.tokenclasses


    defined_policies = []

    for tok in tokenclasses.keys():
        tclass = tokenclasses.get(tok)
        tclt = newToken(tclass)
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

