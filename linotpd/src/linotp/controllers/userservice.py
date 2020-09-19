# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

"""
userservice controller -
     This is the controller for the user self service
     interface, where an authenitcated users can manage their own tokens

There are three types of requests
  * the context requests: before, context
  * the auth requests: auth, userinfo
  * the admin requests

At least all admin request must provide the auth cookie and the username
- the auth cookie is verified by decryption
- the username is checked for valid policy acceptance

Remarks:
 * the userinfo request could use the cookie check as it is running after
   the authorization request,  but no policy definition is required
 * the context request might as well run for an authenticated user, thus
   auth request but no policy check

"""

import base64
import logging

import os

try:
    import json
except ImportError:
    import simplejson as json

import webob

from pylons import request
from pylons import response
from pylons import config
from pylons import tmpl_context as c


from pylons.controllers.util import abort

from pylons.templating import render_mako as render
from mako.exceptions import CompileException

from linotp.lib.base import BaseController
from linotp.lib.auth.validate import ValidationHandler
from linotp.lib.challenges import Challenges

from linotp.lib.policy import (checkPolicyPre,
                               checkPolicyPost,
                               PolicyException,
                               getOTPPINEncrypt,
                               checkOTPPINPolicy,
                               get_client_policy,
                               )

from linotp.lib.reply import (sendResult,
                              sendError,
                              sendQRImageResult,
                              create_img,
                              create_img_src
                              )

from linotp.lib.util import (generate_otpkey,
                             get_client,
                             remove_empty_lines
                             )

from linotp.lib.realm import getDefaultRealm
from linotp.lib.realm import getRealms

from linotp.lib.user import (getUserInfo,
                             getRealmBox,
                             User,
                             getUserId,
                             splitUser)

from linotp.lib.token import (resetToken,
                              setPin,
                              setPinUser,
                              getTokenRealms,
                              get_multi_otp,
                              getTokenType,
                              getTokens4UserOrSerial,
                              )

from linotp.tokens import tokenclass_registry

from linotp.lib.token import TokenHandler

from linotp.tokens.ocra.ocratoken import OcraTokenClass

from linotp.lib.apps import (create_google_authenticator,
                             create_oathtoken_url
                             )

from pylons.i18n.translation import _

from linotp.lib.audit.base import (logTokenNum,
                                   search as audit_search
                                   )

from linotp.lib.userservice import (get_userinfo,
                                    get_cookie_authinfo,
                                    check_session,
                                    get_pre_context,
                                    get_context,
                                    create_auth_cookie,
                                    getTokenForUser,
                                    remove_auth_cookie,
                                    )

from linotp.model import Session

from linotp.lib.resolver import getResolverObject

from linotp.lib.error import ParameterError

from linotp.lib.context import request_context

from linotp.lib.reporting import token_reporting

log = logging.getLogger(__name__)
audit = config.get('audit')

ENCODING = "utf-8"

# -------------------------------------------------------------------------- --

# provide secure cookies for production evironments

secure_cookie = True

# in the development environment where we run in debug or uniTest mode
# there is probaly no https defined. So we switch secure cookies only off
# if the url is not https

if config.get('debug') is True or config.get('unitTest') in [True, 'True']:

    try:
        app_url = request.application_url
    except TypeError:
        app_url = ''

    if not app_url.startswith('https://'):
        secure_cookie = False

# -------------------------------------------------------------------------- --


class UserNotFound(Exception):
    pass


def get_auth_user(request):
    """
    retrieve the authenticated user either from
    selfservice or userservice api / remote selfservice

    :param request: the request object
    :return: tuple of (authentication type and authenticated user and
                        authentication state)
    """

    # ---------------------------------------------------------------------- --

    # for the form based selfservice we have the 'user_selfservice' cookie

    selfservice_cookie = request.cookies.get('user_selfservice')

    if selfservice_cookie:
        user, _client, state, _state_data = get_cookie_authinfo(
                                                    selfservice_cookie)
        auth_type = "user_selfservice"

        return auth_type, user, state

    # ---------------------------------------------------------------------- --

    # for the remote selfservice or userservice api via /userservice/auth
    # we have the 'userauthcookie'

    remote_selfservice_cookie = request.cookies.get('userauthcookie')

    if remote_selfservice_cookie:
        user, _client, state, _state_data = get_cookie_authinfo(
                                                    remote_selfservice_cookie)
        auth_type = "userservice"

        return auth_type, user, state

    return 'unauthenticated', None, None


class UserserviceController(BaseController):
    """
    the interface from the service into linotp to execute the actions for the
    user in the scope of the selfservice

    after the login, the selfservice user gets an auth cookie, which states
    that he already has been authenticated. This cookie is provided on every
    request during which the auth_cookie and session is verified
    """

    def __before__(self, action, **parameters):
        """
        every request to the userservice must pass this place
        here we can check the authorisation for each action and the
        per request general available information
        """

        self.client = get_client(request) or ''

        context = get_pre_context(self.client)

        # ------------------------------------------------------------------ --

        # build up general available variables

        self.mfa_login = context['mfa_login']
        self.autoassign = context['autoassign']
        self.autoenroll = context['autoenroll']

        # ------------------------------------------------------------------ --

        # setup the audit for general availibility

        c.audit = request_context['audit']
        c.audit['success'] = False
        c.audit['client'] = self.client

        # ------------------------------------------------------------------ --

        # the following actions dont require an authenticated session

        if action in ['auth', 'pre_context', 'login', 'logout']:

            return

        # ------------------------------------------------------------------ --

        # every action other than auth, login and pre_context requires a valid
        # session and cookie

        auth_type, identity, auth_state = get_auth_user(request)

        if (not identity or
           auth_type not in ["userservice", 'user_selfservice']):

            abort(403, _("No valid session"))

        # ------------------------------------------------------------------ --

        # make the authenticated user global available

        self.authUser = identity

        c.user = identity.login
        c.realm = identity.realm

        # ------------------------------------------------------------------ --

        # finally check the validty of the session

        if not check_session(request, self.authUser, self.client):

            abort(403, _("No valid session"))

        # ------------------------------------------------------------------ --

        # the usertokenlist could be catched in any identified state

        if action in ['usertokenlist', 'userinfo']:

            return

        # ------------------------------------------------------------------ --

        # any other action requires a full ' state

        if auth_state != 'authenticated':

            abort(403, _("No valid session"))

        # ------------------------------------------------------------------ --

        return

    def __after__(self, action):
        '''
        '''
        try:
            if c.audit['action'] not in ['userservice/context',
                                         'userservice/pre_context',
                                         'userservice/userinfo',
                                         'userservice/load_form'
                                         ]:

                if hasattr(self, 'authUser') and not self.authUser.is_empty:
                    c.audit['user'] = self.authUser.login
                    c.audit['realm'] = self.authUser.realm
                else:
                    c.audit['user'] = ''
                    c.audit['realm'] = ''

                log.debug("[__after__] authenticating as %s in realm %s!"
                          % (c.audit['user'], c.audit['realm']))

                if 'serial' in self.request_params:
                    serial = self.request_params['serial']
                    c.audit['serial'] = serial
                    c.audit['token_type'] = getTokenType(serial)

                if action in ['assign', 'unassign', 'enable', 'disable',
                              'enroll', 'delete', 'activateocratoken',
                              'finishocra2token', 'finishocratoken']:
                    event = 'token_' + action

                    if c.audit.get('source_realm'):
                        source_realms = c.audit.get('source_realm')
                        token_reporting(event, source_realms)

                    target_realms = c.audit.get('realm')
                    token_reporting(event, target_realms)

                audit.log(c.audit)
                Session.commit()

            return response

        except Exception as acc:
            # the exception, when an abort() is called if forwarded
            log.exception("[__after__::%r] webob.exception %r" % (action, acc))
            raise acc

    def _identify_user(self, params):
        """
        identify the user from the request parameters

        the idea of the processing was derived from the former selfservice
        user identification and authentication:
                lib.user.get_authenticated_user
        and has been adjusted to the need to run the password authentication
        as a seperate step

        :param params: request parameters
        :return: User Object or None
        """

        try:
            username = params['login']
        except KeyError as exx:
            log.error("Missing Key: %r", exx)
            return None

        realm = params.get('realm', '').strip().lower()

        # if we have an realmbox, we take the user as it is
        # - the realm is always given

        if getRealmBox():
            user = User(username, realm, "")
            if user.exists():
                return user

        # if no realm box is given
        #    and realm is not empty:
        #    - create the user from the values (as we are in auto_assign, etc)
        if realm and realm in getRealms():
            user = User(username, realm, "")
            if user.exists():
                return user

        # if the realm is empty or no realm parameter or realm does not exist
        #     - the user could live in the default realm
        else:
            def_realm = getDefaultRealm()
            if def_realm:
                user = User(username, def_realm, "")
                if user.exists():
                    return user

        # if any explicit realm handling had no success, we end up here
        # with the implicit realm handling:

        login, realm = splitUser(username)
        user = User(login, realm)
        if user.exists():
            return user

        return None

###############################################################################
# authentication hooks

    def auth(self):
        """
        user authentication for example to the remote selfservice

        :param login: login name of the user normaly in the user@realm format
        :param realm: the realm of the user
        :param password: the password for the user authentication
                         which is base32 encoded to seperate the
                         os_passw:pin+otp in case of mfa_login

        :return: {result : {value: bool} }
        :rtype: json dict with bool value
        """

        try:

            param = self.request_params

            # -------------------------------------------------------------- --

            # identify the user

            user = self._identify_user(params=param)
            if not user:
                log.info("User %r not found", param.get('login'))
                c.audit['action_detail'] = ("User %r not found" %
                                            param.get('login'))
                c.audit['success'] = False
                return sendResult(response, False, 0)

            uid = "%s@%s" % (user.login, user.realm)

            self.authUser = user

            # -------------------------------------------------------------- --

            # extract password

            try:
                password = param['password']
            except KeyError as exx:

                log.info("Missing password for user %r", uid)
                c.audit['action_detail'] = ("Missing password for user %r"
                                            % uid)
                c.audit['success'] = False
                return sendResult(response, False, 0)

            (otp, passw) = password.split(':')
            otp = base64.b32decode(otp)
            passw = base64.b32decode(passw)

            # -------------------------------------------------------------- --

            # check the authentication

            if self.mfa_login:

                res = self._mfa_login_check(user, passw, otp)

            else:

                res = self._default_auth_check(user, passw, otp)

            if not res:

                log.info("User %r failed to authenticate!", uid)
                c.audit['action_detail'] = ("User %r failed to authenticate!"
                                            % uid)
                c.audit['success'] = False
                return sendResult(response, False, 0)

            # -------------------------------------------------------------- --

            log.debug("Successfully authenticated user %s:", uid)

            (cookie, expires,
             expiration) = create_auth_cookie(user, self.client)

            response.set_cookie('userauthcookie', cookie,
                                secure=secure_cookie,
                                expires=expires)

            c.audit['action_detail'] = "expires: %s " % expiration
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, True, 0)

        except Exception as exx:

            c.audit['info'] = ("%r" % exx)[:80]
            c.audit['success'] = False

            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def _login_with_cookie(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step, so that the
          authentication state is either 'credentials_verified' or
          'challenge_triggered'

        :param cookie: preserving the authentication state
        :param params: the request parameters
        """
        user, _client, auth_state, _state_data = get_cookie_authinfo(cookie)

        if not user:
            raise UserNotFound('no user info in authentication cache')

        request_context['selfservice'] = {
            'state': auth_state,
            'user': user
            }

        if auth_state == 'credentials_verified':
            return self._login_with_cookie_credentials(cookie, params)

        elif auth_state == 'challenge_triggered':
            return self._login_with_cookie_challenge(cookie, params)

        else:
            raise NotImplementedError('unknown state %r' % auth_state)

    def _login_with_cookie_credentials(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step, so that the
          authentication state is 'credentials_verified'

        :param cookie: preserving the authentication state

        :param params: the request parameters
        """

        user, _client, _auth_state, _state_data = get_cookie_authinfo(cookie)


        # -------------------------------------------------------------- --

        otp = params.get('otp', '')
        serial = params.get('serial')

        vh = ValidationHandler()

        if 'serial' in params:
            res, reply = vh.checkSerialPass(
                                        serial, passw=otp, options=params)
        else:
            res, reply = vh.checkUserPass(user, passw=otp, options=params)

        # -------------------------------------------------------------- --

        # if res is True: success for direct authentication and we can
        # set the cookie for successful authenticated

        if res:
            ret = create_auth_cookie(user, self.client)
            (cookie, expires, _exp) = ret

            response.set_cookie('user_selfservice', cookie,
                                secure=secure_cookie,
                                expires=expires)

            c.audit['info'] = ("User %r authenticated from otp" % user)

            Session.commit()
            return sendResult(response, res, 0)

        # -------------------------------------------------------------- --

        # if res is False and reply is provided, a challenge was triggered
        # and we set the state 'challenge_triggered'

        if not res and reply:

            if 'message' in reply and "://chal/" in reply['message']:
                reply['img_src'] = create_img_src(reply['message'])

            ret = create_auth_cookie(
                user, self.client, state='challenge_triggered', state_data=reply
            )
            cookie, expires, expiration = ret

            response.set_cookie('user_selfservice', cookie,
                                secure=secure_cookie,
                                expires=expires)

            c.audit['success'] = False

            Session.commit()
            return sendResult(response, False, 0, opt=reply)

        # -------------------------------------------------------------- --

        # if no reply and res is False, the authentication failed

        if not res and not reply:

            Session.commit()
            return sendResult(response, False, 0)

    def _login_with_cookie_challenge(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step and a challenge
          has been triggered, so that the authentication state is
          'challenge_triggered'

        :param cookie: preserving the authentication state
        :param params: the request parameters
        """
        user, _client, _auth_state, state_data = get_cookie_authinfo(cookie)

        if not state_data:
            raise Exception('invalid state data')

        # if there has been a challenge triggerd before, we can extract
        # the the transaction info from the cookie cached data

        transid = state_data.get('transactionid')

        _exp, challenges = Challenges.get_challenges(transid=transid)
        if not challenges:
            log.info("cannot login with challenge as challenges are expired!")
            abort(401, _('challenge expired!'))

        if 'otp' in params:

            params['transactionid'] = transid

            otp_value = params['otp']

            vh = ValidationHandler()
            res, _reply = vh.check_by_transactionid(
                transid, passw=otp_value, options=params)


            c.audit['success'] = res

            if res:
                (cookie, expires,
                 expiration) = create_auth_cookie(user, self.client)

                response.set_cookie('user_selfservice', cookie,
                                    secure=secure_cookie,
                                    expires=expires)

                c.audit['action_detail'] = "expires: %s " % expiration
                c.audit['info'] = "%r logged in " % user

            Session.commit()
            return sendResult(response, res, 0)

        # -------------------------------------------------------------- --

        # if there is no otp in the request, we assume that we
        # have to poll for the transaction state

        verified = False
        transid = state_data.get('transactionid')

        va = ValidationHandler()
        ok, opt = va.check_status(transid=transid, user=user,
                                  serial=None, password='passw',
                                  )
        if ok and opt and opt.get('transactions', {}).get(transid):
            verified = opt.get(
                'transactions', {}).get(
                    transid).get(
                        'valid_tan')

        if verified:
            (cookie, expires,
             expiration) = create_auth_cookie(user, self.client)

            response.set_cookie('user_selfservice', cookie,
                                secure=secure_cookie,
                                expires=expires)
            c.audit['action_detail'] = "expires: %s " % expiration
            c.audit['info'] = "%r logged in " % user

        Session.commit()
        return sendResult(response, verified, 0)


    def _login_with_otp(self, user, passw, param):
        """
        handle login with otp - either if provided directly or delayed

        :param user: User Object of the identified user
        :param password: the password parameter
        :param param: the request parameters
        """

        if not user.checkPass(passw):

            log.info("User %r failed to authenticate!", user)
            c.audit['action_detail'] = ("User %r failed to authenticate!"
                                        % user)
            c.audit['success'] = False

            Session.commit()
            return sendResult(response, False, 0)

        # ------------------------------------------------------------------ --

        # if there is an otp, we can do a direct otp authentication

        otp = param.get('otp', '')
        if otp:

            vh = ValidationHandler()
            res, reply = vh.checkUserPass(user, passw + otp)

            if res:
                log.debug("Successfully authenticated user %r:", user)

                (cookie, expires,
                 expiration) = create_auth_cookie(user, self.client)

                response.set_cookie('user_selfservice', cookie,
                                    secure=secure_cookie,
                                    expires=expires)

                c.audit['action_detail'] = "expires: %s " % expiration
                c.audit['info'] = "%r logged in " % user

            elif not res and reply:
                log.error("challenge trigger though otp is provided")

            c.audit['success'] = res

            Session.commit()
            return sendResult(response, res, 0, reply)

        # ------------------------------------------------------------------ --

        # last step - we have no otp but mfa_login request - so we
        # create the 'credentials_verified state'

        (cookie, expires,
         expiration) = create_auth_cookie(
                            user, self.client,
                            state='credentials_verified')

        response.set_cookie('user_selfservice', cookie,
                            secure=secure_cookie,
                            expires=expires)
        reply = {'message': 'credential verified - '
                 'additional authentication parameter required'}

        c.audit['action_detail'] = "expires: %s " % expiration
        c.audit['info'] = "%r credentials verified" % user

        c.audit['success'] = True
        Session.commit()

        return sendResult(response, False, 0, opt=reply)

    def _login_with_password_only(self, user, password):
        """
        simple old password authentication

        :param user: the identified user
        :param password: the password
        """

        res = user.checkPass(password)

        if res:
            (cookie, expires,
             _expiration) = create_auth_cookie(user, self.client)

            response.set_cookie('user_selfservice', cookie,
                                secure=secure_cookie,
                                expires=expires)

        c.audit['success'] = res
        c.audit['info'] = "%r logged in " % user

        Session.commit()

        return sendResult(response, res, 0)

    def login(self):
        """
        user authentication for example to the remote selfservice

        parameters:

            login: login name of the user normaly in the user@realm format
            realm: the realm of the user
            password: the password for the user authentication
            otp: optional the otp

        return: {result : {value: bool} }
        """

        try:
            param = self.request_params.copy()

            # -------------------------------------------------------------- --

            # if this is an pre-authenticated login we continue
            # with the authentication states

            user_selfservice_cookie = request.cookies.get('user_selfservice')

            # check if this cookie is still valid

            auth_info = get_cookie_authinfo(user_selfservice_cookie)

            if (auth_info[0] and
                check_session(request, auth_info[0], auth_info[1])):

                return self._login_with_cookie(user_selfservice_cookie, param)

            # if there is a cookie but could not be found in cache
            # we remove the out dated client cookie

            if user_selfservice_cookie and not auth_info[0]:

                response.delete_cookie('user_selfservice')

                abort(401, _("No valid session!"))

            # -------------------------------------------------------------- --

            # identify the user

            user = self._identify_user(params=param)
            if not user:
                raise UserNotFound('user %r not found!' % param.get('login'))

            self.authUser = user

            # -------------------------------------------------------------- --

            password = param['password']

            if self.mfa_login:

                # allow the mfa login for users that have no token till now
                # if the policy 'mfa_passOnNoToken' is defined with password
                # only

                tokenArray = getTokenForUser(self.authUser)

                policy = get_client_policy(
                    client=self.client, scope='selfservice',
                    action='mfa_passOnNoToken', userObj=user, active_only=True)

                if policy and not tokenArray:

                    return self._login_with_password_only(user, password)

                return self._login_with_otp(user, password, param)

            else:

                return self._login_with_password_only(user, password)

            # -------------------------------------------------------------- --

        except (webob.exc.HTTPUnauthorized, webob.exc.HTTPForbidden) as exx:

            log.error('userservice login failed: %r', exx)

            c.audit['info'] = ("%r" % exx)[:80]
            c.audit['success'] = False

            return exx

        except Exception as exx:

            log.error('userservice login failed: %r', exx)

            c.audit['info'] = ("%r" % exx)[:80]
            c.audit['success'] = False

            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()

    def _default_auth_check(self, user, password, otp=None):
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

    def _mfa_login_check(self, user, password, otp):
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
                    pin+otp for standard authentication (respects
                                                            otppin ploicy)

        :return: bool
        """
        ret = False

        passwd_match = self._default_auth_check(user, password, otp)

        if passwd_match:
            toks = getTokenForUser(user, active=True)

            # if user has no token, we check for auto assigneing one to him
            if len(toks) == 0:
                th = TokenHandler()

                # if no token and otp, we might do an auto assign
                if self.autoassign and otp:
                    ret = th.auto_assignToken(password + otp, user)

                # if no token no otp, we might trigger an aouto enroll
                elif self.autoenroll and not otp:
                    (auto_enroll_return, reply) = th.auto_enrollToken(password,
                                                                      user)
                    if auto_enroll_return is False:
                        error = ("autoenroll: %r" % reply.get('error', ''))
                        raise Exception(error)
                    # we always have to return a false, as we have
                    # a challenge tiggered
                    ret = False

            # user has at least one token, so we do a check on pin + otp
            else:
                vh = ValidationHandler()
                (ret, _reply) = vh.checkUserPass(user, otp)
        return ret

    def usertokenlist(self):
        '''
        This returns a tokenlist as html output
        '''

        try:
            if self.request_params.get('active', '').lower() in ['true']:
                active = True
            elif self.request_params.get('active', '').lower() in ['false']:
                active = True
            else:
                active = None

            tokenArray = getTokenForUser(self.authUser, active=active,
                                         exclude_rollout=False)

            Session.commit()
            return sendResult(response, tokenArray, 0)

        except Exception as exx:
            log.exception("failed with error: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def userinfo(self):
        """
        hook for the auth, which requests additional user info
        """

        try:

            uinfo = get_userinfo(self.authUser)

            c.audit['success'] = True

            Session.commit()
            return sendResult(response, uinfo, 0)

        except Exception as exx:
            Session.rollback()
            error = ('error (%r) ' % exx)
            log.exception(error)
            return '<pre>%s</pre>' % error

        finally:
            Session.close()

    def logout(self):
        """
        hook for the auth, which requests additional user info
        """

        try:

            cookie = request.cookies.get('user_selfservice')
            remove_auth_cookie(cookie)
            response.delete_cookie('user_selfservice')
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, True, 0)

        except Exception as exx:
            Session.rollback()
            error = ('error (%r) ' % exx)
            log.exception(error)
            return '<pre>%s</pre>' % error

        finally:
            Session.close()
            log.debug('done')




###############################################################################
# context setup functionsa
    def pre_context(self):
        '''
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be
        authenticated. The _before_ is executed before any other function
        in this controller.
        '''
        try:
            pre_context = get_pre_context(self.client)
            response.content_type = 'application/json'
            return json.dumps(pre_context, indent=3)

        except Exception as e:
            log.exception("failed with error: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()

    def context(self):
        '''
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be
        authenticated. The _before_ is executed before any other function
        in this controller.
        '''

        try:

            user = self.authUser.login
            realm = self.authUser.realm

            context = get_context(config, user, realm, self.client)

            response.content_type = 'application/json'
            return json.dumps(context, indent=3)

        except Exception as e:
            log.exception("[context] failed with error: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()

    def load_form(self):
        '''
        This shows the enrollment form for a requested token type.

        implicit parameters are:

        :param type: token type
        :param scope: defines the rendering scope

        :return: rendered html of the requested token
        '''
        res = ''

        try:
            try:
                act = self.request_params["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            try:
                (tok, section, scope) = act.split('.')
            except Exception:
                return res

            if section != 'selfservice':
                return res

            user = self.authUser.login
            realm = self.authUser.realm

            context = get_context(config, user, realm, self.client)
            for k, v in context.items():
                setattr(c, k, v)

            if tok in tokenclass_registry:
                tclt = tokenclass_registry.get(tok)
                if hasattr(tclt, 'getClassInfo'):
                    sections = tclt.getClassInfo(section, {})
                    if scope in sections.keys():
                        section = sections.get(scope)
                        page = section.get('page')
                        c.scope = page.get('scope')
                        c.authUser = self.authUser
                        html = page.get('html')
                        res = render(os.path.sep + html)
                        res = remove_empty_lines(res)

            Session.commit()
            c.audit['success'] = True
            return res

        except CompileException as exx:
            log.exception("[load_form] compile error while processing %r.%r:" %
                                                                (tok, scope))
            log.exception("[load_form] %r" % exx)
            Session.rollback()
            raise exx

        except Exception as exx:
            Session.rollback()
            error = ('error (%r) accessing form data for: %r' % exx)
            log.exception(error)
            return '<pre>%s</pre>' % error

        finally:
            Session.close()

# action hooks for the js methods #############################################
    def enable(self):
        """
        enables a token or all tokens of a user

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = self.request_params
        res = {}
        log.debug("remoteservice enable to enable/disable a token")

        try:
            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userenable', param,
                           authUser=self.authUser)
            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("[userenable] user %s@%s is enabling his token with "
                         "serial %s." % (self.authUser.login,
                                         self.authUser.realm, serial))
                ret = th.enableToken(True, None, serial)
                res["enable token"] = ret

                c.audit['realm'] = self.authUser.realm
                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[enable] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[enable] failed: %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

########################################################
    def disable(self):
        """
        disables a token

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = self.request_params
        res = {}
        log.debug("remoteservice disable a token")

        try:

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userdisable', param,
                           authUser=self.authUser)
            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is disabling his token with serial %s."
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = th.enableToken(False, None, serial)
                res["disable token"] = ret

                c.audit['realm'] = self.authUser.realm
                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("failed: %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def delete(self):
        '''
        This is the internal delete token function that is called from within
        the self service portal. The user is only allowed to delete token,
        that belong to him.
        '''
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userdelete', param, self.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("[userdelete] user %s@%s is deleting his token with "
                         "serial %s." % (self.authUser.login,
                                         self.authUser.realm, serial))
                ret = th.removeToken(serial=serial)
                res["delete token"] = ret

                c.audit['realm'] = self.authUser.realm
                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[userdelete] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userdelete] deleting token %s of user %s failed! %r"
                      % (serial, c.user, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def reset(self):
        '''
        This internally resets the failcounter of the given token.
        '''
        res = {}
        param = self.request_params
        serial = None

        try:
            checkPolicyPre('selfservice', 'userreset', param, self.authUser)
            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("[userreset] user %s@%s is resetting the failcounter"
                                " of his token with serial %s"
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = resetToken(serial=serial)
                res["reset Failcounter"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("error resetting token with serial %s: %r"
                      % (serial, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def unassign(self):
        '''
        This is the internal unassign function that is called from within
        the self service portal. The user is only allowed to unassign token,
        that belong to him.
        '''
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userunassign', param, self.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            upin = param.get("pin", None)

            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is unassigning his token with serial %s."
                         % (self.authUser.login, self.authUser.realm, serial))

                ret = th.unassignToken(serial, None, upin)
                res["unassign token"] = ret

                c.audit['success'] = ret
                c.audit['realm'] = self.authUser.realm

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("unassigning token %s of user %s failed! %r"
                       % (serial, c.user, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def setpin(self):
        '''
        When the user hits the set pin button, this function is called.
        '''
        res = {}
        param = self.request_params

        # # if there is a pin
        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'usersetpin', param, self.authUser)

            try:
                userPin = param["userpin"]
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is setting the OTP PIN "
                         "for token with serial %s" %
                         (self.authUser.login, self.authUser.realm, serial))

                check_res = checkOTPPINPolicy(userPin, self.authUser)

                if not check_res['success']:
                    log.warning("Setting of OTP PIN for Token %s"
                                " by user %s failed: %s" %
                                        (serial, self.authUser.login,
                                         check_res['error']))

                    return sendError(response, _("Error: %s")
                                                        % check_res['error'])

                if 1 == getOTPPINEncrypt(serial=serial,
                                         user=self.authUser):
                    param['encryptpin'] = "True"
                ret = setPin(userPin, None, serial, param)
                res["set userpin"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.exception("policy failed: %r" % pex)
            Session.rollback()
            return sendError(response, unicode(pex), 1)

        except Exception as exx:
            log.exception("Error setting OTP PIN: %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()

    def setmpin(self):
        '''
        When the user hits the set pin button, this function is called.
        '''
        res = {}
        param = self.request_params
        # # if there is a pin
        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'usersetmpin', param, self.authUser)
            try:
                pin = param["pin"]
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is setting the mOTP PIN"
                         " for token with serial %s"
                          % (self.authUser.login, self.authUser.realm, serial))
                ret = setPinUser(pin, serial)
                res["set userpin"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.exception("policy failed: %r" % pex)
            Session.rollback()
            return sendError(response, unicode(pex), 1)

        except Exception as exx:
            log.exception("Error setting the mOTP PIN %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()

    def resync(self):
        '''
        This is the internal resync function that is called from within
        the self service portal
        '''

        res = {}
        param = self.request_params
        serial = "N/A"

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userresync', param, self.authUser)

            try:
                serial = param["serial"]
                otp1 = param["otp1"]
                otp2 = param["otp2"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            th = TokenHandler()
            if (True == th.isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is resyncing his "
                          "token with serial %s"
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = th.resyncToken(otp1, otp2, None, serial)
                res["resync Token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("error resyncing token with serial %s:%r"
                       % (serial, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def assign(self):
        '''
        This is the internal assign function that is called from within
        the self service portal
        '''
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userassign', param, self.authUser)

            upin = param.get("pin", None)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            # check if token is in another realm
            realm_list = getTokenRealms(serial)
            if (not self.authUser.realm.lower() in realm_list
                        and len(realm_list)):
                # if the token is assigned to realms, then the user must be in
                # one of the realms, otherwise the token can not be assigned
                raise Exception(_("The token you want to assign is "
                                             " not contained in your realm!"))
            th = TokenHandler()
            if (False == th.hasOwner(serial)):
                log.info("user %s@%s is assign the token with "
                                                    "serial %s to himself."
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = th.assignToken(serial, self.authUser, upin)
                res["assign token"] = ret

                c.audit['realm'] = self.authUser.realm
                c.audit['success'] = ret
            else:
                raise Exception(_("The token is already assigned "
                                             "to another user."))

            checkPolicyPost('selfservice', 'userassign', param, self.authUser)

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[userassign] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("[userassign] token assignment failed! %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()

    def getSerialByOtp(self):
        '''
         method:
            selfservice/usergetSerialByOtp

        description:
            searches for the token, that generates the given OTP value.
            The search can be restricted by several critterions
            This method only searches tokens in the realm of the user
            and tokens that are not assigned!

        arguments:
            otp      - required. Will search for the token, that produces
                       this OTP value
            type     - optional, will only search in tokens of type

        returns:
            a json result with the serial


        exception:
            if an error occurs an exception is serialized and returned

        '''
        param = self.request_params
        res = {}
        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'usergetserialbyotp', param,
                                self.authUser)
            try:
                otp = param["otp"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            ttype = param.get("type", None)

            c.audit['token_type'] = ttype
            th = TokenHandler()
            serial, _username, _resolverClass = th.get_serial_by_otp(None,
                    otp, 10, typ=ttype, realm=self.authUser.realm, assigned=0)
            res = {'serial': serial}

            c.audit['success'] = 1
            c.audit['serial'] = serial

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("token getSerialByOtp failed! %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()

    def enroll(self):
        '''
        enroll token
        '''
        response_detail = {}
        param = self.request_params.copy()

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userinit', param, self.authUser)

            try:
                tok_type = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            serial = param.get('serial', None)
            prefix = param.get('prefix', None)

            th = TokenHandler()
            if not serial:
                serial = th.genSerial(tok_type, prefix)
                param['serial'] = serial

            desc = param.get("description", '')
            otppin = param.get("otppin")

            log.info("[userinit] initialize a token with serial %s "
                     "and type %s by user %s@%s"
                % (serial, tok_type, self.authUser.login, self.authUser.realm))

            log.debug("[userinit] Initializing the token serial: %s,"
                      " desc: %s, otppin: %s for user %s @ %s." %
            (serial, desc, otppin, self.authUser.login, self.authUser.realm))
            log.debug(param)

            # extend the interface by parameters, so that decisssion could
            # be made in the token update method
            param['::scope::'] = {'selfservice': True,
                                  'user': self.authUser
                                  }

            (ret, tokenObj) = th.initToken(param, self.authUser)
            if tokenObj is not None and hasattr(tokenObj, 'getInfo'):
                info = tokenObj.getInfo()
                response_detail.update(info)

            # result enrichment - if the token is sucessfully created,
            # some processing info is added to the result document,
            #  e.g. the otpkey :-) as qr code
            initDetail = tokenObj.getInitDetail(param, self.authUser)
            response_detail.update(initDetail)

            # -------------------------------------------------------------- --

            c.audit['serial'] = response_detail.get('serial', '')
            c.audit['success'] = ret
            c.audit['user'] = self.authUser.login
            c.audit['realm'] = self.authUser.realm

            logTokenNum(c.audit)
            c.audit['success'] = ret

            # -------------------------------------------------------------- --

            # in the checkPolicyPost for selfservice, the serial is used

            if 'serial' not in param:
                param['serial'] = response_detail.get('serial', '')

            # -------------------------------------------------------------- --

            checkPolicyPost('selfservice', 'enroll', param, user=self.authUser)

            Session.commit()

            # # finally we render the info as qr image, if the qr parameter
            # # is provided and if the token supports this
            if 'qr' in param and tokenObj is not None:
                (rdata, hparam) = tokenObj.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam['qr'] = param.get('qr') or 'html'
                return sendQRImageResult(response, rdata, hparam)
            else:
                return sendResult(response, ret, opt=response_detail)

        except PolicyException as pe:
            log.exception("[userinit] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userinit] token initialization failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def webprovision(self):
        '''
        This function is called, when the create OATHtoken button is hit.
        This is used for web provisioning. See:
            http://code.google.com/p/oathtoken/wiki/WebProvisioning
            and
            http://code.google.com/p/google-authenticator/wiki/KeyUriFormat

        in param:
            type: valid values are "oathtoken" and "googleauthenticator" and
                        "googleauthenticator_time"
        It returns the data and the URL containing the HMAC key
        '''
        log.debug("[userwebprovision] calling function")
        param = self.request_params.copy()

        try:
            ret = {}
            ret1 = False

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userwebprovision',
                           param, self.authUser)

            typ = param["type"]
            t_type = "hmac"

            serial = param.get('serial', None)
            prefix = param.get('prefix', None)

            desc = ""
            # date = datetime.datetime.now().strftime("%y%m%d%H%M%S")
            # rNum = random.randrange(1000, 9999)
            th = TokenHandler()

            if typ.lower() == "oathtoken":
                t_type = 'hmac'
                desc = "OATHtoken web provisioning"

                if prefix is None:
                    prefix = 'LSAO'
                if serial is None:
                    serial = th.genSerial(t_type, prefix)

                # deal: 32 byte. We could use 20 bytes.
                # we must take care, that the url is not longer than 119 chars.
                # otherwise qrcode.js will fail.Change to 32!
                # Usually the URL is 106 bytes long
                otpkey = generate_otpkey(20)

                log.debug("[userwebprovision] Initializing the token serial:"
                          " %s, desc: %s for user %s @ %s." %
                          (serial, desc, self.authUser.login,
                           self.authUser.realm))

                (ret1, _tokenObj) = th.initToken({'type': t_type,
                                'serial': serial,
                                'description': desc,
                                'otpkey': otpkey,
                                'otplen': 6,
                                'timeStep': 30,
                                'timeWindow': 180,
                                'hashlib': "sha1"
                                }, self.authUser)

                if ret1:
                    url = create_oathtoken_url(self.authUser.login,
                                               self.authUser.realm,
                                               otpkey, serial=serial)
                    ret = {
                        'url': url,
                        'img': create_img(url, width=300, alt=serial),
                        'key': otpkey,
                        'name': serial,
                        'serial': serial,
                        'timeBased': False,
                        'counter': 0,
                        'numDigits': 6,
                        'lockdown': True
                    }

            elif typ.lower() in ["googleauthenticator",
                                 "googleauthenticator_time"]:
                desc = "Google Authenticator web prov"

                # ideal: 32 byte.
                otpkey = generate_otpkey(32)
                t_type = "hmac"
                if typ.lower() == "googleauthenticator_time":
                    t_type = "totp"

                if prefix is None:
                    prefix = "LSGO"
                if serial is None:
                    serial = th.genSerial(t_type, prefix)

                log.debug("Initializing the token serial: "
                          "%s, desc: %s for user %s @ %s." %
                        (serial, desc, self.authUser.login,
                         self.authUser.realm))

                (ret1, _tokenObj) = th.initToken({'type': t_type,
                                'serial': serial,
                                'otplen': 6,
                                'description': desc,
                                'otpkey': otpkey,
                                'timeStep': 30,
                                'timeWindow': 180,
                                'hashlib': "sha1"
                                }, self.authUser)

                if ret1:
                        pparam = {'user.login': self.authUser.login,
                                  'user.realm': self.authUser.realm,
                                  'otpkey': otpkey,
                                  'serial': serial,
                                  'type': t_type,
                                  'description': desc,
                                  }
                        url = create_google_authenticator(pparam,
                                                user=self.authUser)
                        label = "%s@%s" % (self.authUser.login,
                                           self.authUser.realm)
                        ret = {
                            'url': url,
                            'img': create_img(url, width=300, alt=serial),
                            'key': otpkey,
                            'label': label,
                            'serial': serial,
                            'counter': 0,
                            'digits': 6,
                        }
            else:
                return sendError(response, _(
                "valid types are 'oathtoken' and 'googleauthenticator' and "
                "'googleauthenticator_time'. You provided %s") % typ)

            logTokenNum(c.audit)
            c.audit['serial'] = serial
            # the Google and OATH are always HMAC; sometimes (FUTURE) totp"
            c.audit['token_type'] = t_type
            c.audit['success'] = ret1
            param['serial'] = serial

            checkPolicyPost('selfservice', 'enroll', param, user=self.authUser)

            Session.commit()
            return sendResult(response, {'init': ret1,
                                         'setpin': False,
                                         'oathtoken': ret})

        except PolicyException as pe:
            log.exception("[userwebprovision] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("[userwebprovision] token initialization failed! %r"
                          % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()

    def getmultiotp(self):
        '''
        Using this function the user may receive OTP values for his own tokens.

        method:
            selfservice/getmultiotp

        arguments:
            serial  - the serial number of the token
            count   - number of otp values to return
            curTime - used ONLY for internal testing: datetime.datetime object

        returns:
            JSON response
        '''

        getotp_active = config.get("linotpGetotp.active")
        if "True" != getotp_active:
            return sendError(response, _("getotp is not activated."), 0)

        param = self.request_params
        ret = {}

        try:
            try:
                serial = param["serial"]
                count = int(param["count"])
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            curTime = param.get("curTime", None)

            th = TokenHandler()
            if (True != th.isTokenOwner(serial, self.authUser)):
                error = (_("The serial %s does not belong to user %s@%s") %
                          (serial, self.authUser.login, self.authUser.realm))
                log.error(error)
                return sendError(response, error, 1)

            max_count = checkPolicyPre('selfservice', 'max_count', param,
                                self.authUser)
            log.debug("checkpolicypre returned %s" % max_count)

            if count > max_count:
                count = max_count

            log.debug("[usergetmultiotp] retrieving OTP value for token %s",
                      serial)
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            if ret['result'] is False and max_count == -1:
                ret['error'] = "%s - %s" % (ret['error'], _("see policy"
                                                            " definition."))

            ret["serial"] = serial
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, ret, 0)

        except PolicyException as pe:
            log.exception("[usergetmultiotp] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[usergetmultiotp] gettoken/getmultiotp failed: %r" % e)
            Session.rollback()
            return sendError(response, _(u"selfservice/usergetmultiotp failed:"
                                         " %r") % e, 0)

        finally:
            Session.close()

    def history(self):
        '''
        This returns the list of the tokenactions of this user
        It returns the audit information for the given search pattern

        method:
            selfservice/userhistory

        arguments:
            key, value pairs as search patterns.

            or: Usually the key=values will be locally AND concatenated.
                it a parameter or=true is passed, the filters will be OR
                concatenated.

            The Flexigrid provides us the following parameters:
                ('page', u'1'), ('rp', u'100'),
                ('sortname', u'number'),
                ('sortorder', u'asc'),
                ('query', u''), ('qtype', u'serial')]
        returns:
            JSON response
        '''

        param = self.request_params
        res = {}

        try:
            log.debug("params: %s" % param)
            checkPolicyPre('selfservice', 'userhistory', param, self.authUser)

            lines, total, page = audit_search(param, user=self.authUser,
                                columns=['date', 'action', 'success', 'serial',
                                        'token_type', 'administrator',
                                        'action_detail', 'info'])

            response.content_type = 'application/json'

            if not total:
                total = len(lines)

            res = {"page": page,
                   "total": total,
                   "rows": lines}

            c.audit['success'] = True

            Session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.exception("[search] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("[search] audit/search failed: %r" % exx)
            Session.rollback()
            return sendError(response, _("audit/search failed: %s")
                                                        % unicode(exx), 0)

        finally:
            Session.close()

    def activateocratoken(self):
        '''

        activateocratoken - called from the selfservice web ui to activate the  OCRA token

        :param type:    'ocra'
        :type type:     string
        :param serial:    serial number of the token
        :type  serial:    string
        :param activationcode: the calculated activation code
        :type  activationcode: string - activationcode format

        :return:    dict about the token
        :rtype:     { 'activate': True, 'ocratoken' : {
                        'url' :     url,
                        'img' :     '<img />',
                        'label' :   "%s@%s" % (self.authUser.login,
                                                   self.authUser.realm),
                        'serial' :  serial,
                    }  }
        '''
        param = self.request_params
        ret = {}

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'useractivateocratoken',
                                                    param, self.authUser)
            try:
                typ = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if typ and typ.lower() not in ["ocra", "ocra2"]:
                return sendError(response, _("valid types are 'ocra' "
                                             "or 'ocra2'. You provided %s")
                                 % typ)

            helper_param = {}
            helper_param['type'] = typ
            try:
                helper_param['serial'] = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            acode = param["activationcode"]
            helper_param['activationcode'] = acode.upper()

            try:
                helper_param['genkey'] = param["genkey"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            th = TokenHandler()
            (ret, tokenObj) = th.initToken(helper_param, self.authUser)

            info = {}
            serial = ""
            if tokenObj is not None:
                info = tokenObj.getInfo()
                serial = tokenObj.getSerial()
            else:
                raise Exception('Token not found!')

            url = info.get('app_import')
            trans = info.get('transactionid')

            ret = {
                'url'       : url,
                'img'       : create_img(url, width=400, alt=url),
                'label'     : "%s@%s" % (self.authUser.login,
                                            self.authUser.realm),
                'serial'    : serial,
                'transaction' : trans,
            }

            logTokenNum(c.audit)

            c.audit['serial'] = serial
            c.audit['token_type'] = typ
            c.audit['success'] = True
            c.audit['realm'] = self.authUser.realm

            Session.commit()
            return sendResult(response, {'activate': True, 'ocratoken': ret})

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("token initialization failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def finshocratoken(self):
        '''

        finshocratoken - called from the selfservice web ui to finish the
                         OCRA token to run the final check_t for the token

        :param passw: the calculated verificaton otp
        :type  passw: string
        :param transactionid: the transactionid
        :type  transactionid: string

        :return:    dict about the token
        :rtype:     { 'result' = ok
                      'failcount' = int(failcount)
                    }

        '''

        param = self.request_params

        try:
            ''' check selfservice authorization '''

            checkPolicyPre('selfservice', 'userwebprovision',
                                                    param, self.authUser)

            try:
                transid = param['transactionid']
                passw = param['pass']
                p_serial = param['serial']
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            value = {}

            ocraChallenge = OcraTokenClass.getTransaction(transid)
            if ocraChallenge is None:
                error = ('[userfinshocratoken] No challenge for transaction'
                            ' %s found' % unicode(transid))
                raise Exception(error)

            serial = ocraChallenge.tokenserial
            if serial != p_serial:
                error = ('[userfinshocratoken] token mismatch for token '
                      'serial: %s - %s' % (unicode(serial), unicode(p_serial)))
                raise Exception(error)

            tokens = getTokens4UserOrSerial(serial=serial)
            if len(tokens) == 0 or len(tokens) > 1:
                error = ('[userfinshocratoken] no token found for '
                         'serial: %s' % (unicode(serial)))
                raise Exception(error)

            theToken = tokens[0]
            tok = theToken.token
            desc = tok.get()
            realms = desc.get('LinOtp.RealmNames')
            if realms is None or len(realms) == 0:
                realm = getDefaultRealm()
            elif len(realms) > 0:
                realm = realms[0]

            userInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver,
                                                        tok.LinOtpIdResClass)
            user = User(login=userInfo.get('username'), realm=realm)

            vh= ValidationHandler()
            (ok, opt) = vh.checkSerialPass(serial, passw, user=user,
                                            options={'transactionid': transid})

            failcount = tokens[0].getFailCount()
            typ = tokens[0].type

            value['result'] = ok
            value['failcount'] = int(failcount)

            c.audit['transactionid'] = transid
            c.audit['token_type'] = typ

            c.audit['success'] = value.get('result')

            checkPolicyPost('selfservice', 'userwebprovision',
                            param, self.authUser)

            Session.commit()
            return sendResult(response, value, opt)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            error = "token finitialization failed! %r" % e
            log.exception(error)
            Session.rollback()
            return sendError(response, error, 1)

        finally:
            Session.close()

# #--
    def finshocra2token(self):
        '''

        finshocra2token - called from the selfservice web ui to finish
                        the OCRA2 token to run the final check_t for the token

        :param passw: the calculated verificaton otp
        :type  passw: string
        :param transactionid: the transactionid
        :type  transactionid: string

        :return:    dict about the token
        :rtype:     { 'result' = ok
                      'failcount' = int(failcount)
                    }

        '''

        param = self.request_params.copy()

        if 'session' in param:
            del param['session']

        value = {}
        ok = False
        typ = ''
        opt = None

        try:
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userwebprovision',
                                                        param, self.authUser)
            passw = param.get("pass", None)
            if not passw:
                raise ParameterError("Missing parameter: pass")

            transid = param.get('state', param.get('transactionid', None))
            if not transid:
                raise ParameterError("Missing parameter: state or "
                                     "transactionid!")

            vh = ValidationHandler()
            (ok, reply) = vh.check_by_transactionid(transid=transid,
                                                    passw=passw,
                                                    options=param)

            value['value'] = ok
            value['failcount'] = int(reply.get('failcount', 0))

            c.audit['transactionid'] = transid
            c.audit['token_type'] = reply['token_type']
            c.audit['success'] = ok
            c.audit['realm'] = self.authUser.realm

            Session.commit()
            return sendResult(response, value, opt)

        except PolicyException as pe:
            log.exception("[userfinshocra2token] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            error = "[userfinshocra2token] token initialization failed! %r" % e
            log.exception(error)
            Session.rollback()
            return sendError(response, error, 1)

        finally:
            Session.close()

    def token_call(self):
        '''
            the generic method call for an dynamic token
        '''
        param = self.request_params.copy()

        res = {}

        try:
            # # method could be part of the virtual url
            context = request.path_info.split('/')
            if len(context) > 2:
                method = context[2]
            else:
                try:
                    method = param["method"]
                except KeyError as exx:
                    raise ParameterError("Missing parameter: '%s'"
                                         % exx.message)

            try:
                typ = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            serial = param.get("serial", None)

            # check selfservice authorization for this dynamic method
            pols = get_client_policy(self.client, scope="selfservice",
                                     realm=self.authUser.realm,
                                     action=method,
                                     userObj=self.authUser.realm,
                                     find_resolver=False)
            if not pols or len(pols) == 0:
                log.error('user %r not authorized to call %s'
                          % (self.authUser, method))
                raise PolicyException('user %r not authorized to call %s'
                                      % (self.authUser, method))

            if typ in tokenclass_registry:
                token_cls = tokenclass_registry.get(typ)
                tclt = None
                if serial is not None:
                    toks = getTokens4UserOrSerial(None, serial, _class=False)
                    tokenNum = len(toks)
                    if tokenNum == 1:
                        token = toks[0]
                        # object method call
                        tclt = token_cls(token)

                # static method call
                if tclt is None:
                    tclt = token_cls
                method = '' + method.strip()
                if hasattr(tclt, method):
                    # TODO: check that method name is a function / method
                    ret = getattr(tclt, method)(param)
                    if len(ret) == 1:
                        res = ret[0]
                    if len(ret) > 1:
                        res = ret[1]
                    c.audit['success'] = res
                else:
                    res['status'] = ('method %s.%s not supported!'
                                    % (typ, method))
                    c.audit['success'] = False

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[token_call] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[token_call] calling method %s.%s of user %s failed! %r"
                      % (typ, method, c.user, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def setdescription(self):
        """
        sets a description for a token

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param description: string containing a new description for the token

        :return: a linotp json doc with result {'status': True, 'value': True}

        """

        log.debug("set token description")

        try:

            param = self.request_params

            serial = param["serial"]
            description = param["description"]

        except KeyError as exx:
            raise ParameterError("Missing parameter: '%s'" % exx)

        try:

            # no policy required, the user must be the token owner though

            th = TokenHandler()

            if not th.isTokenOwner(serial, self.authUser):
                raise "User %r is not owner of the token" % self.authUser.login

            log.info("user %s@%s is changing description of token with "
                     "serial %s.",
                     self.authUser.login, self.authUser.realm, serial)

            ret = th.setDescription(description, None, serial)

            res = {"set description": ret}

            c.audit['realm'] = self.authUser.realm
            c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("failed: %r", exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()

#eof##########################################################################
