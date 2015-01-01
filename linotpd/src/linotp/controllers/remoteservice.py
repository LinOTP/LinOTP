# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
remoteservice controller -
     This is the controller for the remote self service
     interface, where a remote process (pylons) with authenitcated users can
     manage their own tokens

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

import traceback
import binascii
import os
import logging
import base64

try:
    import json
except ImportError:
    import simplejson as json

from Crypto.Cipher import AES

from pylons import (request,
                     response,
                     config,
                     tmpl_context as c
                     )

from pylons.templating import render_mako as render

from linotp.model.meta import Session

from linotp.lib.base import BaseController

from linotp.lib.policy import (checkPolicyPre,
                               checkPolicyPost,
                               PolicyException,
                               getOTPPINEncrypt,
                               getSelfserviceActions,
                               checkOTPPINPolicy,
                               get_client_policy,
                               )

from linotp.lib.reply import (sendResult,
                              sendError,
                              sendQRImageResult,
                              create_img
                              )

from linotp.lib.util import (get_version,
                             get_copyright_info,
                             generate_otpkey,
                             get_client
                             )

from linotp.lib.realm import getDefaultRealm, getRealms

from linotp.lib.selfservice import get_imprint

from linotp.lib.user import (getUserInfo,
                              User,
                              getRealmBox,
                              getUserId)

from linotp.lib.resolver import getResolverObject

from linotp.lib.token import (enableToken,
                              isTokenOwner,
                              removeToken,
                              resetToken,
                              unassignToken,
                              setPin,
                              setPinUser,
                              resyncToken,
                              getTokenRealms,
                              hasOwner,
                              assignToken,
                              get_serial_by_otp,
                              getTokens4UserOrSerial,
                              initToken,
                              genSerial,
                              newToken,
                              get_multi_otp,
                              getTokenType,
                              getTokensOfType,
                              checkUserPass,
                              auto_enrollToken,
                              auto_assignToken,
                              )

from linotp.lib.apps import (create_google_authenticator_url,
                             create_oathtoken_url
                             )

from pylons.i18n.translation import _

from linotp.lib.audit.base import (logTokenNum,
                                   search as audit_search
                                   )

log = logging.getLogger(__name__)
audit = config.get('audit')

ENCODING = "utf-8"


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

# encrypted cookie data

def encrypt(key, data, iv=None):
    if iv is None:
        iv = key
        padding = (16 - len(iv) % 16) % 16
        iv += padding * "\0"
        iv = iv[:16]

    # convert data from binary to hex as it might contain unicode++
    input_data = binascii.b2a_hex(data)
    input_data += u"\x01\x02"
    padding = (16 - len(input_data) % 16) % 16
    input_data += padding * "\0"
    aes = AES.new(key, AES.MODE_CBC, iv)
    res = aes.encrypt(input_data)
    return res

def decrypt(key, data, iv=None):
    if iv is None:
        iv = key
        padding = (16 - len(iv) % 16) % 16
        iv += padding * "\0"
        iv = iv[:16]

    aes = AES.new(key, AES.MODE_CBC, iv)
    output = aes.decrypt(data)
    eof = output.rfind(u"\x01\x02")
    if eof >= 0: output = output[:eof]

    # convert output from ascii, back to bin data, which might be unicode++
    res = binascii.a2b_hex(output)
    return res

def create_auth_cookie(user):
    """
    """
    secret = get_cookie_secret()

    username = user
    if type(user) == User:
        username = "%s@%s" % (user.login, user.realm)

    auth_cookie = binascii.hexlify(encrypt(secret, username))
    check_auth_cookie(username, auth_cookie)
    return auth_cookie

def check_auth_cookie(user, cookie):
    """
    """
    secret = get_cookie_secret()

    try:
        auth_cookie_val = decrypt(secret, binascii.unhexlify(cookie))
    except:
        return False

    username = user
    if type(user) == User:
        username = "%s@%s" % (user.login, user.realm)

    return (username == auth_cookie_val)

def get_cookie_secret():
    """
    """
    if hasattr(config, 'repoze_auth_secret') == False:
        secret = binascii.hexlify(os.urandom(16))
        setattr(config, 'repoze_auth_secret', secret)

    return config.repoze_auth_secret


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

def get_context(user, realm, client):
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

    context["dynamic_actions"] = add_dynamic_selfservice_enrollment(actions)

    # TODO: to establish all token local defined policies
    additional_policies = add_dynamic_selfservice_policies(actions)
    for policy in additional_policies:
        context[policy] = -1

    # TODO: add_local_policies() currently not implemented!!
    context["otplen"] = -1
    context["totp_len"] = -1

    return context

class RemoteserviceController(BaseController):
    """
    the interface from the remote service into linotp to execute the
    selfservice actions

    after the login, the selfservice user gets an auth cookie, which states
    that he already has been authenticated.

    TODO:
    - make the rendering language aware - we have to put in the the client some
      code to transfer the langue to linotp
    - verify the auth_cookie and session

    """

    def __before__(self, action, **params):
        # if action is not auth:
        # - check if there is a cookie in the headers
        # - if this cookie is valid
        # check if user in param and cookie matches
        # check if user is allowed to run action

        params = {}
        if action not in ['auth', 'pre_context']:
            params.update(request.params)
            try:
                userid = params['user']
            except KeyError as keyerr:
                raise Exception('missing parameter %r' % keyerr)

            login, realm = userid.split("@")
            self.authUser = User(login, realm)
            # get cookies from request
            # check_auth_cookie()
            # check_user_policy(scope='selfservice', action='action')

        self.client = get_client()
        context = get_pre_context(self.client)
        self.secure_auth = context['secure_auth']
        self.autoassign = context['autoassign']
        self.autoenroll = context['autoenroll']

        audit.initialize()
        c.audit['success'] = False
        c.audit['client'] = self.client

        self.set_language()
        return

    def __after__(self, action, **params):
        '''

        '''
        param = request.params

        try:
            if c.audit['action'] not in ['remoteservice/context',
                                         'remoteservice/pre_context',
                                         ]:

                if hasattr(self, 'authUser') and not self.authUser.isEmpty():
                    c.audit['user'] = self.authUser.login
                    c.audit['realm'] = self.authUser.realm
                else:
                    c.audit['user'] = ''
                    c.audit['realm'] = ''

                log.debug("[__after__] authenticating as %s in realm %s!"
                          % (c.audit['user'], c.audit['realm']))


                c.audit['success'] = True

                if param.has_key('serial'):
                    c.audit['serial'] = param['serial']
                    c.audit['token_type'] = getTokenType(param['serial'])

                audit.log(c.audit)

            return response

        except Exception as acc:
            # # the exception, when an abort() is called if forwarded
            log.error("[__after__::%r] webob.exception %r" % (action, acc))
            log.error("[__after__] %s" % traceback.format_exc())
            Session.rollback()
            Session.close()
            raise acc

###############################################################################
# authentication hooks

    def auth(self):
        """
        user authentication for example to the remote selfservice

        :param login: login name of the user normaly in the user@realm format
        :param realm: the realm of the user
        :param password: the password for the user authentication
                         which is base32 encoded to seperate the
                         os_passw:pin+otp in case of secure_auth

        :return: {result : {value: bool} }
        :rtype: json dict with bool value
        """

        ok = False
        param = {}

        try:
            param.update(request.params)
            login = param['login']
            password = param['password']
        except KeyError as exx:
            return sendError(response, "Missing Key: %r" % exx)

        try:

            (otp, passw) = password.split(':')
            otp = base64.b32decode(otp)
            passw = base64.b32decode(passw)

            user = User()
            if '@' in login:
                user, rrealm = login.split("@")
                user = User(user, rrealm)
            else:
                realm = getDefaultRealm()
                user = User(login, realm)

            uid = "%s@%s" % (user.login, user.realm)

            if self.secure_auth:
                res = self._secure_auth_check(user, passw, otp)
            else:
                res = self._default_auth_check(user, passw, otp)

            if res:
                log.debug("Successfully authenticated user %s:" % uid)
                cookie = create_auth_cookie(user)
                response.set_cookie('userauthcookie' , cookie, max_age=180 * 24 * 360)
                ok = uid
            else:
                log.info("User %s failed to authenticate!" % uid)

            return sendResult(response, ok, 0)

        except Exception as exx:
            return sendError(response, exx)

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


    def userinfo(self):
        """
        hook for the repoze auth, which requests additional user info
        """
        param = {}

        try:
            param.update(request.params)
            login = param['username']
        except KeyError as exx:
            return sendError(response, "Missing Key: %r" % exx)

        try:
            if '@' in login:
                uuser, rrealm = login.split("@")
                user = User(uuser, rrealm)
            else:
                realm = getDefaultRealm()
                user = User(login, realm)

            (uid, resolver, resolver_class) = getUserId(user)
            uinfo = getUserInfo(uid, resolver, resolver_class)
            if 'cryptpass' in uinfo:
                del uinfo['cryptpass']
            Session.commit()
            return sendResult(response, uinfo, 0)


        except Exception as exx:
            Session.rollback()
            error = ('error (%r) ' % exx)
            log.error(error)
            log.error("[load_form] %s" % traceback.format_exc())
            return '<pre>%s</pre>' % error

        finally:
            Session.close()
            log.debug('[load_form] done')


###############################################################################
# context setup functionsa

    def pre_context(self):
        '''
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be authenticated
        The _before_ is executed before any other function in this controller.
        '''
        param = {}
        try:
            param.update(request.params)

            context = get_pre_context(self.client)
            response.content_type = 'application/json'
            return json.dumps(context, indent=3)

        except Exception as e:
            log.error("[before] failed with error: %r" % e)
            log.error("[before] %s" % traceback.format_exc())
            Session.rollback()
            Session.close()
            return sendError(response, e)

        finally:
            log.debug('[before] done')


    def context(self):
        '''
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be authenticated
        The _before_ is executed before any other function in this controller.
        '''
        param = {}
        try:
            param.update(request.params)
            user = param['user']

            if "@" in user:
                user, realm = user.split('@')
            else:
                realm = getDefaultRealm()

            context = get_context(user, realm, self.client)
            response.content_type = 'application/json'
            return json.dumps(context, indent=3)

        except KeyError as err:
            log.error("[context] failed with error: %r" % err)
            log.error("[context] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, "required parameter: %r" % err)

        except Exception as e:
            log.error("[context] failed with error: %r" % e)
            log.error("[context] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug('[context] done')

# action hooks for the js methods #############################################
    def enable (self):
        """
        enables a token or all tokens of a user

        as this is a controller method, the parameters are taken from
        request.params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = {}
        res = {}
        log.debug("remoteservice enable to enable/disable a token")

        try:
            param.update(request.params)
            serial = param["serial"]
            userid = param['user']
            login, realm = userid.split("@")
            authUser = User(login, realm)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userenable', param, authUser=authUser)

            if (True == isTokenOwner(serial, authUser)):
                log.info("[userenable] user %s@%s is enabling his token with serial %s."
                            % (authUser.login, authUser.realm, serial))
                ret = enableToken(True, None, serial)
                res["enable token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[enable] policy failed %r" % pe)
            log.error("[enable] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("[enable] failed: %r" % e)
            log.error("[enable] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[enable] done')

########################################################
    def disable (self):
        """
        disables a token

        as this is a controller method, the parameters are taken from
        request.params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = {}
        res = {}
        log.debug("remoteservice disable a token")

        try:
            param.update(request.params)
            serial = param["serial"]

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userdisable', param,
                           authUser=self.authUser)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is disabling his token with serial %s."
                            % (self.authUser.login, self.authUser.realm, serial))
                ret = enableToken(False, None, serial)
                res["disable token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("policy failed %r" % pe)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("failed: %r" % e)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def delete(self):
        '''
        This is the internal delete token function that is called from within the self service portal
        The user is only allowed to delete token, that belong to him.
        '''
        param = {}
        res = {}

        try:
            param.update(request.params)
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userdelete', param, self.authUser)

            serial = param["serial"]

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("[userdelete] user %s@%s is deleting his token with serial %s."
                            % (self.authUser.login, self.authUser.realm, serial))
                ret = removeToken(serial=serial)
                res["delete token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[userdelete] policy failed: %r" % pe)
            log.error("[userdelete] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("[userdelete] deleting token %s of user %s failed! %r"
                      % (serial, c.user, e))
            log.error("[userdelete] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[userdelete] done')

    def reset(self):
        '''
        This internally resets the failcounter of the given token.
        '''
        res = {}
        param = {}
        serial = None

        try:
            param.update(request.params)
            checkPolicyPre('selfservice', 'userreset', param, self.authUser)

            serial = param["serial"]

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("[userreset] user %s@%s is resetting the failcounter"
                                " of his token with serial %s"
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = resetToken(serial=serial)
                res["reset Failcounter"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r" % pe)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("error resetting token with serial %s: %r"
                      % (serial, e))
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def unassign(self):
        '''
        This is the internal unassign function that is called from within
        the self service portal. The user is only allowed to unassign token,
        that belong to him.
        '''
        param = {}
        res = {}

        try:
            # check selfservice authorization
            param.update(request.params)
            checkPolicyPre('selfservice', 'userunassign', param, self.authUser)

            serial = param["serial"]
            upin = param.get("pin", None)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is unassigning his "
                                                        "token with serial %s."
                         % (self.authUser.login, self.authUser.realm, serial))
                # TODO: In what realm will the unassigned token be? We should
                # handle this in the unassign Function
                ret = unassignToken(serial, None, upin)
                res["unassign token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r" % pe)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("unassigning token %s of user %s failed! %r"
                       % (serial, c.user, e))
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def setpin(self):
        '''
        When the user hits the set pin button, this function is called.
        '''
        res = {}
        param = {}

        # # if there is a pin
        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'usersetpin', param, self.authUser)

            userPin = param["userpin"]
            serial = param["serial"]

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is setting the OTP PIN "
                         "for token with serial %s" %
                         (self.authUser.login, self.authUser.realm, serial))

                check_res = checkOTPPINPolicy(userPin, self.authUser)

                if not check_res['success']:
                    log.warning("Setting of OTP PIN for Token %s"
                                " by user %s failed: %s" %
                                        (serial, c.user, check_res['error']))
                    return sendError(response, _("Error: %s")
                                                        % check_res['error'])

                if 1 == getOTPPINEncrypt(serial=serial,
                                         user=User(c.user, "", c.realm)):
                    param['encryptpin'] = "True"
                ret = setPin(userPin, None, serial, param)
                res["set userpin"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.error("policy failed: %r" % pex)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pex), 1)

        except Exception as exx:
            log.error("Error setting OTP PIN: %r" % exx)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()
            log.debug('done')

    def setmpin(self):
        '''
        When the user hits the set pin button, this function is called.
        '''
        res = {}
        param = {}
        # # if there is a pin
        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'usersetmpin', param, self.authUser)

            pin = param["pin"]
            serial = param["serial"]

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is setting the mOTP PIN"
                         " for token with serial %s"
                          % (self.authUser.login, self.authUser.realm, serial))
                ret = setPinUser(pin, serial)
                res["set userpin"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.error("policy failed: %r" % pex)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pex), 1)

        except Exception as exx:
            log.error("Error setting the mOTP PIN %r" % exx)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()
            log.debug('done')

    def resync(self):
        '''
        This is the internal resync function that is called from within the self service portal
        '''

        res = {}
        param = {}
        serial = "N/A"

        try:
            param.update(request.params)
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userresync', param, self.authUser)

            serial = param["serial"]
            otp1 = param["otp1"]
            otp2 = param["otp2"]

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is resyncing his "
                          "token with serial %s"
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = resyncToken(otp1, otp2, None, serial)
                res["resync Token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r" % pe)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("error resyncing token with serial %s:%r"
                       % (serial, e))
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def assign(self):
        '''
        This is the internal assign function that is called from within
        the self service portal
        '''
        param = {}
        res = {}

        try:
            param.update(request.params)
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userassign', param, self.authUser)

            upin = param.get("pin", None)
            serial = param["serial"]

            # check if token is in another realm
            realm_list = getTokenRealms(serial)
            if (not self.authUser.realm.lower() in realm_list
                        and len(realm_list)):
                # if the token is assigned to realms, then the user must be in
                # one of the realms, otherwise the token can not be assigned
                raise Exception(_("The token you want to assign is "
                                             " not contained in your realm!"))

            if (False == hasOwner(serial)):
                log.info("user %s@%s is assign the token with "
                                                    "serial %s to himself."
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = assignToken(serial, self.authUser, upin)
                res["assign token"] = ret

                c.audit['success'] = ret
            else:
                raise Exception(_("The token is already assigned "
                                             "to another user."))

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[userassign] policy failed: %r" % pe)
            log.error("[userassign] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.error("[userassign] token assignment failed! %r" % exx)
            log.error("[userassign] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()
            log.debug('[userassign] done')


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
        param = {}
        res = {}
        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'usergetserialbyotp', param,
                                                                self.authUser)

            otp = param["otp"]
            ttype = param.get("type", 'hmac')

            c.audit['token_type'] = ttype
            serial, _username, _resolverClass = get_serial_by_otp(None,
                    otp, 10, typ=ttype, realm=self.authUser.realm, assigned=0)
            res = {'serial' : serial}

            c.audit['success'] = 1
            c.audit['serial'] = serial

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r" % pe)
            log.error("%s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.error("token getSerialByOtp failed! %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            log.debug('done')
            Session.close()

    def enroll(self):
        '''
        enroll token
        '''
        log.debug("[userinit] calling function")


        response_detail = {}
        param = {}

        try:
            param.update(request.params)

            # check selfservice authorization

            checkPolicyPre('selfservice', 'userinit', param, self.authUser)

            tok_type = param["type"]

            serial = param.get('serial', None)
            prefix = param.get('prefix', None)

            if not serial:
                serial = genSerial(tok_type, prefix)
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

            (ret, tokenObj) = initToken(param, self.authUser)
            if tokenObj is not None and hasattr(tokenObj, 'getInfo'):
                info = tokenObj.getInfo()
                response_detail.update(info)

            # # result enrichment - if the token is sucessfully created,
            # # some processing info is added to the result document,
            # #  e.g. the otpkey :-) as qr code
            initDetail = tokenObj.getInitDetail(param, self.authUser)
            response_detail.update(initDetail)

            c.audit['success'] = ret
            c.audit['user'] = self.authUser.login
            c.audit['realm'] = self.authUser.realm

            logTokenNum()
            c.audit['success'] = ret
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
            log.error("[userinit] policy failed: %r" % pe)
            log.error("[userinit] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("[userinit] token initialization failed! %r" % e)
            log.error("[userinit] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[userinit] done')


    def webprovision(self):
        '''
        This function is called, when the create OATHtoken button is hit.
        This is used for web provisioning. See:
            http://code.google.com/p/oathtoken/wiki/WebProvisioning
            and
            http://code.google.com/p/google-authenticator/wiki/KeyUriFormat

        in param:
            type: valid values are "oathtoken" and "googleauthenticator" and "googleauthenticator_time"
        It returns the data and the URL containing the HMAC key
        '''
        log.debug("[userwebprovision] calling function")
        param = {}

        try:

            ret = {}
            ret1 = False
            ret2 = False
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userwebprovision', param, self.authUser)

            typ = param["type"]
            t_type = "hmac"

            serial = param.get('serial', None)
            prefix = param.get('prefix', None)

            desc = ""
            # date = datetime.datetime.now().strftime("%y%m%d%H%M%S")
            # rNum = random.randrange(1000, 9999)

            if typ.lower() == "oathtoken":
                t_type = 'hmac'
                desc = "OATHtoken web provisioning"

                if prefix is None:
                    prefix = 'LSAO'
                if serial is None:
                    serial = genSerial(t_type, prefix)

                # deal: 32 byte. We could use 20 bytes.
                # we must take care, that the url is not longer than 119 chars.
                # otherwise qrcode.js will fail.Change to 32!
                # Usually the URL is 106 bytes long
                otpkey = generate_otpkey(20)

                log.debug("[userwebprovision] Initializing the token serial: %s, desc: %s for user %s @ %s." %
                        (serial, desc, self.authUser.login, self.authUser.realm))
                (ret1, tokenObj) = initToken({ 'type': t_type,
                                'serial': serial,
                                'description' : desc,
                                'otpkey' : otpkey,
                                'otplen' : 6,
                                'timeStep' : 30,
                                'timeWindow' : 180,
                                'hashlib' : "sha1"
                                }, self.authUser)

                if ret1:
                    url = create_oathtoken_url(self.authUser.login, self.authUser.realm , otpkey, serial=serial)
                    ret = {
                        'url' : url,
                        'img' : create_img(url, width=300, alt=serial),
                        'key' : otpkey,
                        'name' : serial,
                        'serial' : serial,
                        'timeBased' : False,
                        'counter' : 0,
                        'numDigits': 6,
                        'lockdown' : True
                    }

            elif typ.lower() in [ "googleauthenticator", "googleauthenticator_time"]:
                desc = "Google Authenticator web prov"

                # ideal: 32 byte.
                otpkey = generate_otpkey(32)
                t_type = "hmac"
                if typ.lower() == "googleauthenticator_time":
                    t_type = "totp"

                if prefix is None:
                    prefix = "LSGO"
                if serial is None:
                    serial = genSerial(t_type, prefix)

                log.debug("Initializing the token serial: "
                          "%s, desc: %s for user %s @ %s." %
                        (serial, desc, self.authUser.login, self.authUser.realm))
                (ret1, tokenObj) = initToken({ 'type': t_type,
                                'serial': serial,
                                'otplen': 6,
                                'description' : desc,
                                'otpkey' : otpkey,
                                'timeStep' : 30,
                                'timeWindow' : 180,
                                'hashlib' : "sha1"
                                }, self.authUser)

                if ret1:
                        url = create_google_authenticator_url(self.authUser.login, self.authUser.realm, otpkey, serial=serial, type=t_type)
                        label = "%s@%s" % (self.authUser.login, self.authUser.realm)
                        ret = {
                            'url' :     url,
                            'img' :     create_img(url, width=300, alt=serial),
                            'key' :     otpkey,
                            'label' :   label,
                            'serial' :  serial,
                            'counter' : 0,
                            'digits':   6,
                        }
            else:
                return sendError(response, _("valid types are 'oathtoken' and 'googleauthenticator' and 'googleauthenticator_time'. You provided %s") % type)

            logTokenNum()
            c.audit['serial'] = serial
            # the Google and OATH are always HMAC; sometimes (FUTURE) totp"
            c.audit['token_type'] = t_type
            c.audit['success'] = ret1

            checkPolicyPost('selfservice', 'enroll', param, user=self.authUser)

            Session.commit()
            return sendResult(response, { 'init': ret1, 'setpin' : False, 'oathtoken' : ret})

        except PolicyException as pe:
            log.error("[userwebprovision] policy failed: %r" % pe)
            log.error("[userwebprovision] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("[userwebprovision] token initialization failed! %r" % e)
            log.error("[userwebprovision] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[userwebprovision] done')

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
        log.debug("[usergetmultiotp] calling function")

        getotp_active = config.get("linotpGetotp.active")
        if "True" != getotp_active:
            return sendError(response, _("getotp is not activated."), 0)

        param = {}
        ret = {}

        try:
            param.update(request.params)
            serial = param["serial"]
            count = int(param["count"])
            curTime = param.get("curTime", None)

            if (True != isTokenOwner(serial, self.authUser)):
                error = (_("The serial %s does not belong to user %s@%s") %
                          (serial, self.authUser.login, self.authUser.realm))
                log.error(error)
                return sendError(response, error, 1)

            max_count = checkPolicyPre('selfservice', 'max_count', param, self.authUser)
            log.debug("checkpolicypre returned %s" % max_count)

            if count > max_count:
                count = max_count

            log.debug("[usergetmultiotp] retrieving OTP value for token %s" % serial)
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            if ret['result'] == False and max_count == -1:
                ret['error'] = "%s - %s" % (ret['error'], _("see policy defintion."))

            ret["serial"] = serial
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, ret , 0)

        except PolicyException as pe:
            log.error("[usergetmultiotp] policy failed: %r" % pe)
            log.error("[usergetmultiotp] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("[usergetmultiotp] gettoken/getmultiotp failed: %r" % e)
            log.error("[usergetmultiotp] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, _(u"selfservice/usergetmultiotp failed: %s")
                             % unicode(e), 0)

        finally:
            Session.close()
            log.debug('[usergetmultiotp] done')

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

        param = {}
        res = {}

        try:
            param.update(request.params)
            log.debug("params: %s" % param)
            checkPolicyPre('selfservice', 'userhistory', param, self.authUser)

            lines, total, page = audit_search(param, user=self.authUser,
                                columns=['date', 'action', 'success', 'serial',
                                        'token_type', 'administrator',
                                        'action_detail', 'info'])

            response.content_type = 'application/json'

            if not total:
                total = len(lines)

            res = { "page" : page,
                "total" : total,
                "rows" : lines }

            c.audit['success'] = True

            Session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.error("[search] policy failed: %r" % pe)
            log.error("[search] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.error("[search] audit/search failed: %r" % exx)
            log.error("[search] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, _("audit/search failed: %s")
                                                        % unicode(exx), 0)

        finally:
            Session.close()
            log.error("[search] done")

##############################################################################

def add_dynamic_selfservice_enrollment(actions):
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


def add_dynamic_selfservice_policies(actions):
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

#eof##########################################################################

