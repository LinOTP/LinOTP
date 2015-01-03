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
""" logic for the userservice processing """

import binascii
import os

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

from linotp.lib.realm import getRealms

from linotp.lib.selfservice import get_imprint

from linotp.lib.user import (
                              getRealmBox,
                             )


from linotp.lib.token import (getTokens4UserOrSerial,
                              newToken,
                              )


from linotp.lib.crypt import (aes_decrypt_data,
                              aes_encrypt_data
                              )


from linotp.lib.user import (getUserInfo,
                              User,
                              getUserId)
from linotp.lib.token import (checkUserPass,
                              auto_enrollToken,
                              auto_assignToken,
                              )

from linotp.lib.resolver import getResolverObject

from linotp.lib.realm import getDefaultRealm

import base64

import logging
log = logging.getLogger(__name__)

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


def auth(login, password, secure_auth=False):

    res = False
    uid = ""
    user = User()

    (otp, passw) = password.split(':')
    otp = base64.b32decode(otp)
    passw = base64.b32decode(passw)


    if '@' in login:
        user, rrealm = login.split("@")
        user = User(user, rrealm)
    else:
        realm = getDefaultRealm()
        user = User(login, realm)

    uid = "%s@%s" % (user.login, user.realm)

    if secure_auth:
        res = _secure_auth_check(user, passw, otp)
    else:
        res = _default_auth_check(user, passw, otp)

    return (res, uid, user)

def _default_auth_check(user, password, otp=None):
    """
    the former selfservice login controll:
     check for username and os_pass

    :param user: user object
    :param password: the expected os_password
    :param otp: not used

    :return: bool
    """
    (uid, _resolver, resolver_class) = getUserId(user)
    r_obj = getResolverObject(resolver_class)
    res = r_obj.checkPass(uid, password)
    return res

def _secure_auth_check(self, user, password, otp):
    """
    secure auth requires the os password and the otp (pin+otp)
    - secure auth supports autoassignement, where the user logs in with
                  os_password and only the otp value. If user has no token,
                  a token with a matching otp in the window is searched
    - secure auth supports autoenrollment, where a user with no token will
                  get automaticaly enrolled one token.

    :param user: user object
    :param password: the os_password
    :param otp: empty (for autoenrollment),
                otp value only for auto assignment or
                pin+otp for standard authentication (respects otppin ploicy)

    :return: bool
    """
    ret = False

    passwd_match = self._default_auth_check(user, password, otp)

    if passwd_match:
        toks = getTokenForUser(user)

        # if user has no token, we check for auto assigneing one to him
        if len(toks) == 0:

            # if no token and otp, we might do an auto assign
            if self.autoassign and otp:
                ret = auto_assignToken(password + otp, user)

            # if no token no otp, we might trigger an aouto enroll
            elif self.autoenroll and not otp:
                (auto_enroll_return, _reply) = auto_enrollToken(password, user)
                if auto_enroll_return is False:
                    log.error("Tryed auto enrollmen but it failed")
                # we always have to return a false, as we have a challenge tiggered
                ret = False

        # user has at least one token, so we do a check on pin + otp
        else:
            (ret, _reply) = checkUserPass(user, otp)
    return ret

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
    :return: the encrypted cookie value
    """
    secret = get_cookie_secret(config)

    username = user
    if type(user) == User:
        username = "%s@%s" % (user.login, user.realm)
    iv = os.urandom(2)
    enc = aes_encrypt_data(username + "|" + client, secret, iv)

    auth_cookie = "%s%s" % (binascii.hexlify(iv), binascii.hexlify(enc))
    return auth_cookie

def check_auth_cookie(config, cookie, user, client):
    """
    verify that value of the auth_cookie contains the correct user and client

    :param user: the authenticated user object
    :param cookie: the auth_cookie
    :param client: the requesting client

    :return: boolean
    """
    secret = get_cookie_secret(config)

    try:
        iv = cookie[:4]
        enc = cookie[4:]
        auth_cookie_val = aes_decrypt_data(binascii.unhexlify(enc),
                                       secret,
                                       binascii.unhexlify(iv))
        cookie_user, cookie_client = auth_cookie_val.split('|')
    except:
        return False

    username = user
    if type(user) == User:
        username = "%s@%s" % (user.login, user.realm)

    return (username == cookie_user and cookie_client == client)

def get_cookie_secret(config):
    """
    get the cookie encryption secret from the repoze config
    - if the selfservice is droped from running localy, this
      configuration option might not exist anymore

    :return: return the cookie encryption secret
    """

    if hasattr(config, 'repoze_auth_secret') == False:
        secret = binascii.hexlify(os.urandom(16))
        setattr(config, 'repoze_auth_secret', secret)

    return config.repoze_auth_secret

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
    of the login page could be controlled if realm_box or secure_auth is
    defined

    :param client: the rendering is client dependend, so we need the info
    :return: context dict, with all rendering attributes
    """

    context = {}
    context["version"] = get_version()
    context["licenseinfo"] = get_copyright_info()

    context["default_realm"] = getDefaultRealm()
    context["realm_box"] = getRealmBox()

    context["realms"] = json.dumps(_get_realms_())


    """
    check for secure_auth, autoassign and autoenroll in policy definition
    """

    context['secure_auth'] = False
    policy = get_client_policy(client=client,
                                scope='selfservice',
                                action='secure_auth')
    if policy:
        context['secure_auth'] = True

    context['autoassign'] = False
    policy = get_client_policy(client=client,
                                scope='enrollment',
                                action='autoassignment')
    if policy:
        context['autoassign'] = True

    context['autoenroll'] = False
    policy = get_client_policy(client=client,
                                scope='enrollment',
                                action='autoenrollment')
    if policy:
        context['autoenroll'] = True

    return context

def get_context(config, user, realm, client):
    """
    get the user dependend rendering context

    :param user: the selfservice user
    :param realm: the selfservice realm
    :param client: the selfservice client info - required for pre_context
    :return: context dict, with all rendering attributes

    """


    context = get_pre_context(client)

    context["user"] = user
    context["realm"] = realm
    authUser = User(user, realm)
    context["imprint"] = get_imprint(context["realm"])
    context["tokenArray"] = getTokenForUser(authUser)

    # show the defined actions, which have a rendering
    actions = getSelfserviceActions(authUser)
    context["actions"] = actions
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
            context[name.strip()] = nval

    context["dynamic_actions"] = add_dynamic_selfservice_enrollment(config, actions)

    # TODO: to establish all token local defined policies
    additional_policies = add_dynamic_selfservice_policies(config, actions)
    for policy in additional_policies:
        context[policy] = -1

    # TODO: add_local_policies() currently not implemented!!
    context["otplen"] = -1
    context["totp_len"] = -1

    return context


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

