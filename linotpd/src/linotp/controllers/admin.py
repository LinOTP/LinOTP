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

"""
admin controller - interfaces to administrate LinOTP
"""
import os
import logging

from pylons import request
from pylons import response
from pylons import config
from pylons import tmpl_context as c

from linotp.lib.base import BaseController
from linotp.lib.tokeniterator import TokenIterator
from linotp.lib.token import TokenHandler

from linotp.lib.token import setPin
from linotp.lib.token import resetToken
from linotp.lib.token import setPinUser
from linotp.lib.token import setPinSo

from linotp.lib.token import setRealms, getTokenType
from linotp.lib.token import getTokens4UserOrSerial
from linotp.lib.token import newToken
from linotp.lib.token import getTokenRealms

from linotp.lib.error import ParameterError
from linotp.lib.error import TokenAdminError

from linotp.lib.util import getParam, getLowerParams
from linotp.lib.util import check_session
from linotp.lib.util import SESSION_KEY_LENGTH

from linotp.lib.util import get_client
from linotp.lib.user import getSearchFields
from linotp.lib.user import getUserListIterators
from linotp.lib.user import User
from linotp.lib.user import getUserFromParam
from linotp.lib.user import getUserFromRequest

from linotp.lib.realm import getDefaultRealm
from linotp.lib.realm import getRealms

from linotp.lib.reply import sendResult
from linotp.lib.reply import sendError
from linotp.lib.reply import sendXMLResult
from linotp.lib.reply import sendXMLError
from linotp.lib.reply import sendCSVResult
from linotp.lib.reply import sendResultIterator

from linotp.lib.reply import sendQRImageResult

from linotp.lib.challenges import Challenges

from linotp.lib.policy import checkPolicyPre
from linotp.lib.policy import checkPolicyPost
from linotp.lib.policy import PolicyException
from linotp.lib.policy import getOTPPINEncrypt

from linotp.lib.audit.base import logTokenNum

# for loading XML file
from linotp.lib.ImportOTP import parseSafeNetXML
from linotp.lib.ImportOTP import parseOATHcsv
from linotp.lib.ImportOTP import ImportException
from linotp.lib.ImportOTP import parseYubicoCSV

from linotp.lib.useriterator import iterate_users
from linotp.lib.context import request_context
from linotp.lib.reporting import token_reporting
from pylons.i18n.translation import _

from linotp.lib.resolver import getResolverClass
from linotp.lib.resolver import prepare_resolver_parameter

# For logout
from webob.exc import HTTPUnauthorized

# this is a hack for the static code analyser, which
# would otherwise show session.close() as error
import linotp.model
Session = linotp.model.Session

audit = config.get('audit')


log = logging.getLogger(__name__)

optional = True
required = False


class AdminController(BaseController):

    '''
    The linotp.controllers are the implementation of the web-API to talk to the LinOTP server.
    The AdminController is used for administrative tasks like adding tokens to LinOTP,
    assigning tokens or revoking tokens.
    The functions of the AdminController are invoked like this

        https://server/admin/<functionname>

    The functions are described below in more detail.
    '''

    def __before__(self, action, **params):
        '''
        '''

        try:

            c.audit = request_context['audit']
            c.audit['success'] = False
            c.audit['client'] = get_client(request)
            # Session handling
            check_session(request)

            request_context['Audit'] = audit
            return request

        except Exception as exx:
            log.exception("[__before__::%r] exception %r", action, exx)
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

    def __after__(self, action):
        '''
        '''
        params = {}

        try:
            # prevent logging of getsession or other irrelevant requests
            if action in ['getsession', 'dropsession']:
                return request

            params.update(request.params)

            c.audit['administrator'] = getUserFromRequest(request).get("login")
            if 'serial' in params:
                    serial = request.params['serial']
                    c.audit['serial'] = serial
                    c.audit['token_type'] = getTokenType(serial)
            if action in ['assign', 'unassign', 'enable', 'disable', 'init',
                          'loadtokens', 'copyTokenUser', 'losttoken',
                          'remove', 'tokenrealm']:
                event = 'token_' + action

                if c.audit.get('source_realm'):
                    source_realms = c.audit.get('source_realm')
                    token_reporting(event, source_realms)

                target_realms = c.audit.get('realm')
                token_reporting(event, target_realms)

            audit.log(c.audit)
            Session.commit()
            return request

        except Exception as e:
            log.exception("[__after__] unable to create a session cookie: %r" % e)
            Session.rollback()
            return sendError(response, e, context='after')

        finally:
            Session.close()

    def logout(self):
        # see http://docs.pylonsproject.org/projects/pyramid/1.0/narr/webob.html
        c.audit['action_detail'] = "logout"
        # response.status = "401 Not authenticated"

        nonce = request.environ.get("nonce")
        realm = request.environ.get("realm")
        detail = "401 Unauthorized"
        # return HTTPUnauthorized(request=request)
        raise HTTPUnauthorized(
             unicode(detail),
             [('WWW-Authenticate', 'Digest realm="%s", nonce="%s", qop="auth"' % (realm, nonce))]
            )

        # raise exc.HTTPUnauthorized(
        #                           str(detail),
        #                           [('WWW-Authenticate', 'Basic realm="%s"' % realm)]
        #                          )
        # abort(401, "You are not authenticated")


    def getsession(self):
        '''
        This generates a session key and sets it as a cookie
        set_cookie is defined in python-webob::

            def set_cookie(self, key, value='', max_age=None,
                   path='/', domain=None, secure=None, httponly=False,
                   version=None, comment=None, expires=None, overwrite=False):
        '''
        import binascii
        try:
            web_host = request.environ.get('HTTP_HOST')
            # HTTP_HOST also contains the port number. We need to stript this!
            web_host = web_host.split(':')[0]
            log.debug("[getsession] environment: %s" % request.environ)
            log.debug("[getsession] found this web_host: %s" % web_host)
            random_key = os.urandom(SESSION_KEY_LENGTH)
            cookie = binascii.hexlify(random_key)
            log.debug("[getsession] adding session cookie %s to response." % cookie)
            # we send all three to cope with IE8
            response.set_cookie('admin_session', value=cookie, domain=web_host)
            # this produces an error with the gtk client
            # response.set_cookie('admin_session', value=cookie,  domain=".%" % web_host )
            response.set_cookie('admin_session', value=cookie, domain="")
            return sendResult(response, True)

        except Exception as e:
            log.exception("[getsession] unable to create a session cookie: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()

    def dropsession(self):
        # request.cookies.pop( 'admin_session', None )
        # FIXME: Does not seem to work
        response.set_cookie('admin_session', None, expires=1)
        return

    def getTokenOwner(self):
        """
        provide the userinfo of the token, which is specified as serial
        """

        param = {}
        ret = {}
        try:
            param.update(request.params)
            serial = param["serial"]

            # check admin authorization
            checkPolicyPre('admin', 'tokenowner', param)
            th = TokenHandler()
            owner = th.getTokenOwner(serial)
            if owner.info:
                ret = owner.info

            c.audit['success'] = len(ret) > 0

            Session.commit()
            return sendResult(response, ret)

        except PolicyException as pe:
            log.exception("Error getting token owner. Exception was %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("Error getting token owner. Exception was %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def show(self):
        """
        method:
            admin/show

        description:
            displays the list of the available tokens

        arguments:
            * serial  - optional: only this serial will be displayed
            * user    - optional: only the tokens of this user will be
                                  displayed. If the user does not exist,
                                  linotp will search tokens of users, who
                                  contain this substring.
                        **TODO:** This can be very time consuming an will be
                                  changed in the next release to use wildcards.
            * filter  - optional: takes a substring to search in table token
                                  columns
            * viewrealm - optional: takes a realm, only the tokens in this
                                    realm will be displayed
            * realm - - optional: alias to the viewrealm
            * sortby  - optional: sort the output by column
            * sortdir - optional: asc/desc
            * page    - optional: reqeuest a certain page
            * pagesize- optional: limit the number of returned tokens
            * user_fields - optional: additional user fields from the userid resolver of the owner (user)
            * outform - optional: if set to "csv", than the token list will be given in CSV

        returns:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        exception:
            if an error occurs an exception is serialized and returned
        """

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            page = getParam(param, "page", optional)
            filter = getParam(param, "filter", optional)
            sort = getParam(param, "sortby", optional)
            dir = getParam(param, "sortdir", optional)
            psize = getParam(param, "pagesize", optional)
            realm = param.get("viewrealm", param.get("realm", ''))
            ufields = getParam(param, "user_fields", optional)
            output_format = getParam(param, "outform", optional)

            user_fields = []
            if ufields:
                user_fields = [u.strip() for u in ufields.split(",")]

            user = getUserFromParam(param)

            filterRealm = []
            # check admin authorization
            res = checkPolicyPre('admin', 'show', param , user=user)

            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            filterRealm = ['*']
            if res['active'] and res['realms']:
                filterRealm = res['realms']

            if realm:
            # If the admin wants to see only one realm, then do it:
                log.debug("Only tokens in realm %s will be shown",
                          realm)
                if realm in filterRealm or '*' in filterRealm:
                    filterRealm = [realm]

            log.info("[show] admin >%s< may display the following realms: %r",
                     res['admin'], filterRealm)

            toks = TokenIterator(user, serial, page, psize, filter, sort, dir,
                                 filterRealm, user_fields)

            c.audit['success'] = True
            c.audit['info'] = "realm: %s, filter: %r" % (filterRealm, filter)

            # put in the result
            result = {}

            # now row by row
            lines = []
            for tok in toks:
                # CKO:
                lines.append(tok)

            result["data"] = lines
            result["resultset"] = toks.getResultSetInfo()

            Session.commit()

            if output_format == "csv":
                return sendCSVResult(response, result)
            else:
                return sendResult(response, result)

        except PolicyException as pe:
            log.exception('[show] policy failed: %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception('[show] failed: %r' % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


########################################################
    def remove(self):
        """
        method:
            admin/remove

        description:
            deletes either a certain token given by serial or all tokens of a user

        arguments:
            * serial  - optional
            * user    - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params

        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param)

            c.audit['user'] = user.login

            if user.is_empty:
                c.audit['realm'] = getTokenRealms(serial)
            else:
                c.audit['realm'] = user.realm
                if c.audit['realm'] == "":
                    realms = set()
                    for tokenserial in getTokens4UserOrSerial(user, serial):
                        realms.union(tokenserial.getRealms())
                    c.audit['realm'] = realms

            # check admin authorization
            checkPolicyPre('admin', 'remove', param)

            th = TokenHandler()
            log.info("[remove] removing token with serial %s for user %s", serial, user.login)
            ret = th.removeToken(user, serial)

            logTokenNum(c.audit)
            c.audit['success'] = ret

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict['message'] = "No tokens for this user"

            Session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.exception("[remove] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[remove] failed! %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


########################################################
    def enable(self):
        """
        method:
            admin/enable

        description:
            enables a token or all tokens of a user

        arguments:
            * serial  - optional
            * user    - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param)

            # check admin authorization
            checkPolicyPre('admin', 'enable', param, user=user)

            th = TokenHandler()
            log.info("[enable] enable token with serial %s for user %s@%s.",
                     serial, user.login, user.realm)
            ret = th.enableToken(True, user, serial)

            c.audit['success'] = ret
            c.audit['user'] = user.login
            logTokenNum(c.audit)

            if user.is_empty:
                c.audit['realm'] = getTokenRealms(serial)
            else:
                c.audit['realm'] = user.realm
                if c.audit['realm'] == "":
                    realms = set()
                    for tokenserial in getTokens4UserOrSerial(user, serial):
                        realms.union(tokenserial.getRealms())
                    c.audit['realm'] = realms

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict['message'] = "No tokens for this user"

            Session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.exception("[enable] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[enable] failed: %r" % e)
            Session.rollback()
            log.error('[enable] error enabling token')
            return sendError(response, e, 1)

        finally:
            Session.close()


########################################################
    def getSerialByOtp(self):
        """
        method:
            admin/getSerialByOtp

        description:
            searches for the token, that generates the given OTP value.
            The search can be restricted by several critterions

        arguments:
            * otp      - required. Will search for the token, that produces this OTP value
            * type     - optional, will only search in tokens of type
            * realm    - optional, only search in this realm
            * assigned - optional. 1: only search assigned tokens, 0: only search unassigned tokens

        returns:
            a json result with the serial


        exception:
            if an error occurs an exception is serialized and returned

        """

        ret = {}
        param = request.params

        try:
            otp = getParam(param, "otp", required)
            typ = getParam(param, "type", optional)
            realm = getParam(param, "realm", optional)
            assigned = getParam(param, "assigned", optional)

            serial = ""
            username = ""

            # check admin authorization
            checkPolicyPre('admin', 'getserial', param)
            th = TokenHandler()
            serial, username, resolverClass = th.get_serial_by_otp(None, otp,
                                                                   10, typ=typ,
                                                realm=realm, assigned=assigned)
            log.debug("[getSerialByOtp] found %s with user %s" %
                      (serial, username))

            if "" != serial:
                checkPolicyPost('admin', 'getserial',
                                {'serial': serial})

            c.audit['success'] = 1
            c.audit['serial'] = serial

            ret['success'] = True
            ret['serial'] = serial
            ret['user_login'] = username
            ret['user_resolver'] = resolverClass

            Session.commit()
            return sendResult(response, ret, 1)

        except PolicyException as pe:
            log.exception("[disable] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            c.audit['success'] = 0
            Session.rollback()
            log.exception('[getSerialByOtp] error: %r' % e)
            return sendError(response, e, 1)

        finally:
            Session.close()


########################################################
    def disable(self):
        """
        method:
            admin/disable

        description:
            disables a token given by serial or all tokens of a user

        arguments:
            * serial  - optional
            * user    - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param)
            auth_user = getUserFromRequest(request)

            # check admin authorization
            checkPolicyPre('admin', 'disable', param, user=user)

            th = TokenHandler()
            log.info("[disable] disable token with serial %s for user %s@%s.",
                     serial, user.login, user.realm)
            ret = th.enableToken(False, user, serial)

            c.audit['success'] = ret
            c.audit['user'] = user.login

            if user.is_empty:
                c.audit['realm'] = getTokenRealms(serial)
            else:
                c.audit['realm'] = user.realm
                if c.audit['realm'] == "":
                    realms = set()
                    for tokenserial in getTokens4UserOrSerial(user, serial):
                        realms.union(tokenserial.getRealms())
                    c.audit['realm'] = realms

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict['message'] = "No tokens for this user"


            Session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.exception("[disable] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[disable] failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()


#######################################################
    def check_serial(self):
        '''
        method
            admin/check_serial

        description:
            This function checks, if a given serial will be unique.
            It returns True if the serial does not yet exist and
            new_serial as a new value for a serial, that does not exist, yet

        arguments:
            serial    - required- the serial to be checked

        returns:
            a json result with a new suggestion for the serial

        exception:
            if an error occurs an exception is serialized and returned

        '''

        param = request.params
        try:
            serial = getParam(param, "serial", required)

            # check admin authorization
            # try:
            #    checkPolicyPre('admin', 'disable', param )
            # except PolicyException as pe:
            #    return sendError(response, str(pe), 1)

            log.info("[check_serial] checking serial %s" % serial)
            th = TokenHandler()
            (unique, new_serial) = th.check_serial(serial)

            c.audit['success'] = True
            c.audit['serial'] = serial
            c.audit['action_detail'] = "%r - %r" % (unique, new_serial)

            Session.commit()
            return sendResult(response, {"unique":unique, "new_serial":new_serial}, 1)

        except PolicyException as pe:
            log.exception("[check_serial] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[check_serial] failed! %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


########################################################
    def init(self):
        """
        method:
            admin/init

        description:
            creates a new token.

        arguments:
            * otpkey (required) the hmac Key of the token
            * genkey (required) =1, if key should be generated.
                We either need otpkey or genkey
            * keysize (optional) either 20 or 32. Default is 20
            * serial (required) the serial number / identifier of the token
            * description (optional)
            * pin (optional) the pin of the user pass
            * user (optional) login user name
            * realm (optional) realm of the user
            * type (optional) the type of the token
            * tokenrealm (optional) the realm a token should be put into
            * otplen (optional) length of the OTP value
            * hashlib (optional) used hashlib sha1 oder sha256

        ocra arguments:
            for generating OCRA Tokens type=ocra you can specify the
            following parameters:

            * ocrasuite (optional) - if you do not want to use the default
                ocra suite OCRA-1:HOTP-SHA256-8:QA64
            * sharedsecret (optional) if you are in Step0 of enrolling an
                OCRA token the sharedsecret=1 specifies,
              that you want to generate a shared secret
            * activationcode (optional) if you are in Step1 of enrolling
                an OCRA token you need to pass the
              activation code, that was generated in the QRTAN-App

        qrtoken arguments:
            for generating QRTokens type=qr you can specify the
            following parameters

            * hashlib (optional) the hash algorithm used in the mac
                calculation (sha512, sha256, sha1). default is sha256

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        ret = False
        response_detail = {}

        try:

            params = dict(request.params)
            params.setdefault('key_size', 20)

            # --------------------------------------------------------------- --

            # determine token class

            token_cls_alias = getParam(params, "type", optional) or 'hmac'

            g = config['pylons.app_globals']
            tokenclasses = g.tokenclasses

            token_cls_aliases = tokenclasses.keys()
            lower_alias = token_cls_alias.lower()

            if lower_alias not in token_cls_aliases:
                raise TokenAdminError('admin/init failed: unknown token '
                                      'type %r' % token_cls_alias, id=1610)

            token_cls_identifier = tokenclasses.get(lower_alias)
            token_cls = newToken(token_cls_identifier)

            # --------------------------------------------------------------- --

            # call the token class hook in order to enrich/overwrite the
            # parameters

            helper_params = token_cls.get_helper_params_pre(params)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            # fetch user from parameters.

            user = getUserFromParam(params)

            # --------------------------------------------------------------- --

            # check admin authorization

            res = checkPolicyPre('admin', 'init', params, user=user)

            # --------------------------------------------------------------- --

            # if no user is given, we put the token in all realms of the admin

            tokenrealm = None
            if user.login == "":
                log.debug("[init] setting tokenrealm %s" % res['realms'])
                tokenrealm = res['realms']

            # --------------------------------------------------------------- --

            helper_params = token_cls.get_helper_params_post(params, user=user)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            serial = params.get('serial', None)
            prefix = params.get('prefix', None)

            # --------------------------------------------------------------- --

            th = TokenHandler()
            if not serial:
                serial = th.genSerial(token_cls_alias, prefix)
                params['serial'] = serial

            log.info("[init] initialize token. user: %s, serial: %s"
                     % (user.login, serial))

            # --------------------------------------------------------------- --

            (ret, token) = th.initToken(params, user,
                                        tokenrealm=tokenrealm)

            # --------------------------------------------------------------- --

            # different token types return different information on
            # initialization (e.g. otpkey, pairing_url, etc)

            initDetail = token.getInitDetail(params, user)
            response_detail.update(initDetail)

            # --------------------------------------------------------------- --

            # prepare data for audit

            if token is not None and ret is True:
                c.audit['serial'] = token.getSerial()
                c.audit['token_type'] = token.type

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm

            if c.audit['realm'] == "":
                c.audit['realm'] = tokenrealm

            logTokenNum(c.audit)
            c.audit['success'] = ret
            # --------------------------------------------------------------- --

            checkPolicyPost('admin', 'init', params, user=user)
            Session.commit()

            # --------------------------------------------------------------- --

            # depending on parameters send back an qr image
            # or a text result

            if 'qr' in params and token is not None:
                (rdata, hparam) = token.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam['qr'] = params.get('qr') or 'html'
                return sendQRImageResult(response, rdata, hparam)
            else:
                return sendResult(response, ret, opt=response_detail)

        # ------------------------------------------------------------------- --

        except PolicyException as pe:
            log.exception("[init] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[init] token initialization failed! %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


########################################################

    def unassign(self):
        """
        method:
            admin/unassign - remove the assigned user from the token

        description:
            unassigns a token from a user. i.e. the binding between the token
            and the user is removed

        arguments:
            * serial    - required - the serial number / identifier of the token
            * user      - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params

        try:

            serial = getParam(param, "serial", required)
            user = getUserFromParam(param)

            c.audit['source_realm'] = getTokenRealms(serial)

            # check admin authorization
            checkPolicyPre('admin', 'unassign', param)

            th = TokenHandler()
            log.info("[unassign] unassigning token with serial %r from "
                     "user %r@%r" % (serial, user.login, user.realm))
            ret = th.unassignToken(serial, user, None)

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm']:
                c.audit['realm'] = getTokenRealms(serial)

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict['message'] = "No tokens for this user"

            Session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.exception('[unassign] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[unassign] failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()


########################################################

    def assign(self):
        """
        method:
            admin/assign

        description:
            assigns a token to a user, i.e. a binding between the token and
            the user is created.

        arguments:
            * serial     - required - the serial number / identifier of the token
            * user       - required - login user name
            * pin        - optional - the pin of the user pass

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params

        try:

            upin = getParam(param, "pin", optional)
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param)

            # check admin authorization
            checkPolicyPre('admin', 'assign', param)

            th = TokenHandler()
            c.audit['source_realm'] = getTokenRealms(serial)
            log.info("[assign] assigning token with serial %s to user %s@%s" % (serial, user.login, user.realm))
            res = th.assignToken(serial, user, upin, param)

            checkPolicyPost('admin', 'assign', param, user)

            c.audit['success'] = res
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm']:
                c.audit['realm'] = getTokenRealms(serial)

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception('[assign] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception('[assign] token assignment failed! %r' % e)
            Session.rollback()
            return sendError(response, e, 0)

        finally:
            Session.close()


########################################################

    def setPin(self):
        """
        method:
            admin/set

        description:
            This function sets the smartcard PINs of a eTokenNG OTP.
            The userpin is used to store the mOTP PIN of mOTP tokens!
            !!! For setting the OTP PIN, use the function /admin/set!

        arguments:
            * serial     - required
            * userpin    - optional: store the userpin
            * sopin      - optional: store the sopin

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        count = 0

        description = "setPin: parameters are\
        serial\
        userpin\
        sopin\
        "
        try:
            param = getLowerParams(request.params)

            # # if there is a pin
            if param.has_key("userpin"):
                msg = "setting userPin failed"
                userPin = getParam(param, "userpin", required)
                serial = getParam(param, "serial", required)

                # check admin authorization
                checkPolicyPre('admin', 'setPin', param)

                log.info("[setPin] setting userPin for token with serial %s" % serial)
                ret = setPinUser(userPin, serial)
                res["set userpin"] = ret
                count = count + 1
                c.audit['action_detail'] += "userpin, "

            if param.has_key("sopin"):
                msg = "setting soPin failed"
                soPin = getParam(param, "sopin", required)
                serial = getParam(param, "serial", required)

                # check admin authorization
                checkPolicyPre('admin', 'setPin', param)

                log.info("[setPin] setting soPin for token with serial %s" % serial)
                ret = setPinSo(soPin, serial)
                res["set sopin"] = ret
                count = count + 1
                c.audit['action_detail'] += "sopin, "

            if count == 0:
                Session.rollback()
                return sendError(response, ParameterError("Usage: %s" % description, id=77))

            c.audit['success'] = count

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception('[setPin] policy failed %r, %r' % (msg, pe))
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception('[setPin] %s :%r' % (msg, e))
            Session.rollback()
            return sendError(response, unicode(e), 0)

        finally:
            Session.close()



########################################################

    def set(self):
        """
        method:
            admin/set

        description:
            this function is used to set many different values of a token.

        arguments:
            * serial     - optional
            * user       - optional
            * pin        - optional - set the OTP PIN
            * MaxFailCount  - optional - set the maximum fail counter of a token
            * SyncWindow    - optional - set the synchronization window of the token
            * OtpLen        - optional - set the OTP Lenght of the token
            * CounterWindow - optional - set the counter window (blank presses)
            * hashlib       - optioanl - set the hashing algo for HMAC tokens. This can be sha1, sha256, sha512
            * timeWindow    - optional - set the synchronize window for timebased tokens (in seconds)
            * timeStep      - optional - set the timestep for timebased tokens (usually 30 or 60 seconds)
            * timeShift     - optional - set the shift or timedrift of this token
            * countAuthSuccessMax    - optional    - set the maximum allowed successful authentications
            * countAuthSuccess\      - optional    - set the counter of the successful authentications
            * countAuth        - optional - set the counter of authentications
            * countAuthMax     - optional - set the maximum allowed authentication tries
            * validityPeriodStart    - optional - set the start date of the validity period. The token can not be used before this date
            * validityPeriodEnd      - optional - set the end date of the validaity period. The token can not be used after this date
            * phone - set the phone number for an SMS token

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        count = 0

        description = "set: parameters are\
        pin\
        MaxFailCount\
        SyncWindow\
        OtpLen\
        CounterWindow\
        hashlib\
        timeWindow\
        timeStep\
        timeShift\
        countAuthSuccessMax\
        countAuthSuccess\
        countAuth\
        countAuthMax\
        validityPeriodStart\
        validityPeriodEnd\
        description\
        phone\
        "
        msg = ""

        try:
            param = getLowerParams(request.params)

            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param)

            # check admin authorization
            checkPolicyPre('admin', 'set', param, user=user)

            th = TokenHandler()
            # # if there is a pin
            if 'pin' in param:
                msg = "[set] setting pin failed"
                upin = getParam(param, "pin", required)
                log.info("[set] setting pin for token with serial %r" % serial)
                if 1 == getOTPPINEncrypt(serial=serial, user=user):
                    param['encryptpin'] = "True"
                ret = setPin(upin, user, serial, param)
                res["set pin"] = ret
                count = count + 1
                c.audit['action_detail'] += "pin, "

            if "MaxFailCount".lower() in param:
                msg = "[set] setting MaxFailCount failed"
                maxFail = int(getParam(param, "MaxFailCount".lower(), required))
                log.info("[set] setting maxFailCount (%r) for token with "
                         "serial %r" % (maxFail, serial))
                ret = th.setMaxFailCount(maxFail, user, serial)
                res["set MaxFailCount"] = ret
                count = count + 1
                c.audit['action_detail'] += "maxFailCount=%d, " % maxFail

            if "SyncWindow".lower() in param:
                msg = "[set] setting SyncWindow failed"
                syncWindow = int(
                    getParam(param, "SyncWindow".lower(), required))
                log.info(
                    "[set] setting syncWindow (%r) for token with serial %r" % (
                    syncWindow, serial))
                ret = th.setSyncWindow(syncWindow, user, serial)
                res["set SyncWindow"] = ret
                count = count + 1
                c.audit['action_detail'] += "syncWindow=%d, " % syncWindow

            if "description".lower() in param:
                msg = "[set] setting description failed"
                description = getParam(param, "description".lower(), required)
                log.info("[set] setting description (%r) for token with serial"
                         " %r" % (description, serial))
                ret = th.setDescription(description, user, serial)
                res["set description"] = ret
                count = count + 1
                c.audit['action_detail'] += "description=%r, " % description

            if param.has_key("CounterWindow".lower()):
                msg = "[set] setting CounterWindow failed"
                counterWindow = int(
                    getParam(param, "CounterWindow".lower(), required))
                log.info(
                    "[set] setting counterWindow (%r) for token with serial %r"
                    % (counterWindow, serial))
                ret = th.setCounterWindow(counterWindow, user, serial)
                res["set CounterWindow"] = ret
                count = count + 1
                c.audit['action_detail'] += "counterWindow=%d, " % counterWindow

            if "OtpLen".lower() in param:
                msg = "[set] setting OtpLen failed"
                otpLen = int(getParam(param, "OtpLen".lower(), required))
                log.info(
                    "[set] setting OtpLen (%r) for token with serial %r" % (
                    otpLen, serial))
                ret = th.setOtpLen(otpLen, user, serial)
                res["set OtpLen"] = ret
                count = count + 1
                c.audit['action_detail'] += "otpLen=%d, " % otpLen

            if "hashlib".lower() in param:
                msg = "[set] setting hashlib failed"
                hashlib = getParam(param, "hashlib".lower(), required)
                log.info(
                    "[set] setting hashlib (%r) for token with serial %r" % (
                    hashlib, serial))
                th = TokenHandler()
                ret = th.setHashLib(hashlib, user, serial)
                res["set hashlib"] = ret
                count = count + 1
                c.audit['action_detail'] += "hashlib=%s, " % unicode(hashlib)

            if "timeWindow".lower() in param:
                msg = "[set] setting timeWindow failed"
                timeWindow = int(
                    getParam(param, "timeWindow".lower(), required))
                log.info("[set] setting timeWindow (%r) for token with serial"
                         " %r" % (timeWindow, serial))
                ret = th.addTokenInfo("timeWindow", timeWindow, user, serial)
                res["set timeWindow"] = ret
                count = count + 1
                c.audit['action_detail'] += "timeWindow=%d, " % timeWindow

            if param.has_key("timeStep".lower()):
                msg = "[set] setting timeStep failed"
                timeStep = int(getParam(param, "timeStep".lower(), required))
                log.info(
                    "[set] setting timeStep (%r) for token with serial %r" % (
                    timeStep, serial))
                ret = th.addTokenInfo("timeStep", timeStep, user, serial)
                res["set timeStep"] = ret
                count = count + 1
                c.audit['action_detail'] += "timeStep=%d, " % timeStep

            if "timeShift".lower() in param:
                msg = "[set] setting timeShift failed"
                timeShift = int(getParam(param, "timeShift".lower(), required))
                log.info("[set] setting timeShift (%r) for token with serial"
                         " %r" % (timeShift, serial))
                ret = th.addTokenInfo("timeShift", timeShift, user, serial)
                res["set timeShift"] = ret
                count = count + 1
                c.audit['action_detail'] += "timeShift=%d, " % timeShift

            if "countAuth".lower() in param:
                msg = "[set] setting countAuth failed"
                ca = int(getParam(param, "countAuth".lower(), required))
                log.info(
                    "[set] setting count_auth (%r) for token with serial %r" % (
                    ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth = int(ca)
                    count = count + 1
                    ret += 1
                res["set countAuth"] = ret
                c.audit['action_detail'] += "countAuth=%d, " % ca

            if "countAuthMax".lower() in param:
                msg = "[set] setting countAuthMax failed"
                ca = int(getParam(param, "countAuthMax".lower(), required))
                log.info(
                    "[set] setting count_auth_max (%r) for token with serial %r"
                    % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth_max = int(ca)
                    count = count + 1
                    ret += 1
                res["set countAuthMax"] = ret
                c.audit['action_detail'] += "countAuthMax=%d, " % ca

            if "countAuthSuccess".lower() in param:
                msg = "[set] setting countAuthSuccess failed"
                ca = int(getParam(param, "countAuthSuccess".lower(), required))
                log.info(
                    "[set] setting count_auth_success (%r) for token with"
                    "serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth_success = int(ca)
                    count = count + 1
                    ret += 1
                res["set countAuthSuccess"] = ret
                c.audit['action_detail'] += "countAuthSuccess=%d, " % ca

            if "countAuthSuccessMax".lower() in param:
                msg = "[set] setting countAuthSuccessMax failed"
                ca = int(
                    getParam(param, "countAuthSuccessMax".lower(), required))
                log.info(
                    "[set] setting count_auth_success_max (%r) for token with"
                    "serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth_success_max = int(ca)
                    count = count + 1
                    ret += 1
                res["set countAuthSuccessMax"] = ret
                c.audit['action_detail'] += "countAuthSuccessMax=%d, " % ca

            if "validityPeriodStart".lower() in param:
                msg = "[set] setting validityPeriodStart failed"
                ca = getParam(param, "validityPeriodStart".lower(), required)
                log.info(
                    "[set] setting validity_period_start (%r) for token with"
                    "serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.validity_period_start = ca
                    count = count + 1
                    ret += 1
                res["set validityPeriodStart"] = ret
                c.audit[
                    'action_detail'] += u"validityPeriodStart=%s, " % unicode(
                    ca)

            if "validityPeriodEnd".lower() in param:
                msg = "[set] setting validityPeriodEnd failed"
                ca = getParam(param, "validityPeriodEnd".lower(), required)
                log.info(
                    "[set] setting validity_period_end (%r) for token with"
                    "serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.validity_period_end = ca
                    count = count + 1
                    ret += 1
                res["set validityPeriodEnd"] = ret
                c.audit['action_detail'] += "validityPeriodEnd=%s, " % unicode(
                    ca)

            if "phone" in param:
                msg = "[set] setting phone failed"
                ca = getParam(param, "phone".lower(), required)
                log.info("[set] setting phone (%r) for token with serial %r" % (
                ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.addToTokenInfo("phone", ca)
                    count = count + 1
                    ret += 1
                res["set phone"] = ret
                c.audit['action_detail'] += "phone=%s, " % unicode(ca)

            if count == 0:
                Session.rollback()
                return sendError(
                    response, ParameterError("Usage: %s" % description,  id=77))

            c.audit['success'] = count
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm

            if c.audit['realm'] == "":
                c.audit['realm'] = getTokenRealms(serial)

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception('[set] policy failed: %s, %r' % (msg, pe))
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx :
            log.exception('%s: %r' % (msg, exx))
            Session.rollback()
            # as this message is directly returned into the javascript
            # alert as escaped string we remove here all escaping chars
            error = "%r" % exx
            error = error.replace('"', '|')
            error = error.replace("'", ':')
            error = error.replace('&', '+')
            error = error.replace('>', ']')
            error = error.replace('<', '[')
            result = "%s: %s" % (msg, error)
            return sendError(response, result)

        finally:
            Session.close()


########################################################
    def resync(self):
        """
        method:
            admin/resync - resync a token to a new counter

        description:
            this function resync the token, if the counter on server side is out of sync
            with the physica token.

        arguments:
            * serial     - serial or user required
            * user       - s.o.
            * otp1       - the next otp to be found
            * otp2       - the next otp after the otp1

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param)

            otp1 = getParam(param, "otp1", required)
            otp2 = getParam(param, "otp2", required)

            ''' to support the challenge based resync, we have to pass the challenges
                down to the token implementation
            '''
            chall1 = getParam(param, "challenge1", optional)
            chall2 = getParam(param, "challenge2", optional)

            options = None
            if chall1 is not None and chall2 is not None:
                options = {'challenge1' : chall1, 'challenge2':chall2 }

            # check admin authorization
            checkPolicyPre('admin', 'resync', param)
            th = TokenHandler()
            log.info("[resync] resyncing token with serial %r, user %r@%r"
                     % (serial, user.login, user.realm))
            res = th.resyncToken(otp1, otp2, user, serial, options)

            c.audit['success'] = res
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm'] and "" != c.audit['user']:
                c.audit['realm'] = getDefaultRealm()

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception('[resync] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception('[resync] resyncing token failed %r' % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()


########################################################
    def userlist(self):
        """
        method:
            admin/userlist - list all users

        description:
            lists the user in a realm

        arguments:
            * <searchexpr> - will be retrieved from the UserIdResolverClass
            * realm	 - a realm, which is a collection of resolver configurations
            * resConf	 - a destinct resolver configuration
            * page    - the number of page, which should be retrieved (optional)
            * rp    - the number of users per page (optional)

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        users = []
        param = {}

        # check admin authorization
        # check if we got a realm or resolver, that is ok!
        try:
            param.update(request.params)
            realm = getParam(param, "realm", optional)
            checkPolicyPre('admin', 'userlist', param)

            up = 0
            user = getUserFromParam(param)

            log.info("[userlist] displaying users with param: %s, ", param)

            if (len(user.realm) > 0):
                up = up + 1
            if (len(user.resolver_config_identifier) > 0):
                up = up + 1

            # Here we need to list the users, that are only visible in the
            # realm!! we could also only list the users in the realm, if the
            # admin got the right "userlist".

            if len(param) == up:
                usage = {"usage": "list available users matching the "
                                    "given search patterns:"}
                usage["searchfields"] = getSearchFields(user)
                res = usage
                Session.commit()
                return sendResult(response, res)

            else:
                list_params = {}
                list_params.update(param)
                if 'session' in list_params:
                    del list_params['session']

                rp = None
                if "rp" in list_params:
                    rp = list_params['rp']
                    del list_params['rp']

                page = None
                if "page" in list_params:
                    page = list_params['page']
                    del list_params['page']

                users_iters = getUserListIterators(list_params, user)
                # TODO: check if admin is allowed to see the useridresolvers
                # as users_iters is (user_iterator, resolvername)
                # we could simply check if the admin is allowed to view the
                # resolver

                c.audit['success'] = True
                c.audit['info'] = "realm: %s" % realm

                Session.commit()

                response.content_type = 'application/json'
                return sendResultIterator(iterate_users(users_iters),
                                          rp=rp, page=page)

        except PolicyException as pe:
            log.exception('[userlist] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userlist] failed %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


########################################################
    def tokenrealm(self):
        '''
        method:
            admin/tokenrealm - set the realms a token belongs to

        description:
            sets the realms of a token

        arguments:
            * serial    - required -  serialnumber of the token
            * realms    - required -  comma seperated list of realms
        '''

        param = request.params
        try:
            serial = getParam(param, "serial", required)
            realms = getParam(param, "realms", required)

            # check admin authorization
            checkPolicyPre('admin', 'tokenrealm', param)

            c.audit['source_realm'] = getTokenRealms(serial)
            log.info("[tokenrealm] setting realms for token %s to %s" % (serial, realms))
            realmList = realms.split(',')
            ret = setRealms(serial, realmList)

            c.audit['success'] = ret
            c.audit['info'] = realms
            c.audit['realm'] = realmList

            Session.commit()
            return sendResult(response, ret, 1)

        except PolicyException as pe:
            log.exception('[tokenrealm] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception('[tokenrealm] error setting realms for token %r' % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()


########################################################

    def reset(self):
        """
        method:
            admin/reset

        description:
            reset the FailCounter of a Token

        arguments:
            user or serial - to identify the tokens

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = request.params

        serial = getParam(param, "serial", optional)
        user = getUserFromParam(param)

        try:

            # check admin authorization
            checkPolicyPre('admin', 'reset', param , user=user)

            log.info("[reset] resetting the FailCounter for token with serial %s" % serial)
            ret = resetToken(user, serial)

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm

            # DeleteMe: This code will never run, since getUserFromParam
            # always returns a realm!
            # if "" == c.audit['realm'] and "" != c.audit['user']:
            #    c.audit['realm'] = getDefaultRealm()

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict['message'] = "No tokens for this user"

            Session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.exception('[reset] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("[reset] Error resetting failcounter %r" % exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


########################################################

    def copyTokenPin(self):
        """
        method:
            admin/copyTokenPin

        description:
            copies the token pin from one token to another

        arguments:
            * from - required - serial of token from
            * to   - required - serial of token to

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        ret = 0
        err_string = ""
        param = request.params

        try:
            serial_from = getParam(param, "from", required)
            serial_to = getParam(param, "to", required)

            # check admin authorization
            checkPolicyPre('admin', 'copytokenpin', param)

            th = TokenHandler()
            log.info("[copyTokenPin] copying Pin from token %s to token %s" % (serial_from, serial_to))
            ret = th.copyTokenPin(serial_from, serial_to)

            c.audit['success'] = ret
            c.audit['serial'] = serial_to
            c.audit['action_detail'] = "from %s" % serial_from

            err_string = unicode(ret)
            if -1 == ret:
                err_string = "can not get PIN from source token"
            if -2 == ret:
                err_string = "can not set PIN to destination token"
            if 1 != ret:
                c.audit['action_detail'] += ", " + err_string
                c.audit['success'] = 0

            Session.commit()
            # Success
            if 1 == ret:
                return sendResult(response, True)
            else:
                return sendError(response, "copying token pin failed: %s" % err_string)

        except PolicyException as pe:
            log.exception("[losttoken] Error doing losttoken %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[copyTokenPin] Error copying token pin")
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


########################################################

    def copyTokenUser(self):
        """
        method:
            admin/copyTokenUser

        description:
            copies the token user from one token to another

        arguments:
            * from - required - serial of token from
            * to   - required - serial of token to

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        ret = 0
        err_string = ""
        param = request.params

        try:

            serial_from = getParam(param, "from", required)
            serial_to = getParam(param, "to", required)

            # check admin authorization
            checkPolicyPre('admin', 'copytokenuser', param)

            th = TokenHandler()
            log.info("[copyTokenUser] copying User from token %s to token %s" % (serial_from, serial_to))
            ret = th.copyTokenUser(serial_from, serial_to)

            c.audit['success'] = ret
            c.audit['serial'] = serial_to
            c.audit['action_detail'] = "from %s" % serial_from
            c.audit['source_realm'] = getTokenRealms(serial_from)
            c.audit['realm'] = getTokenRealms(serial_to)

            err_string = unicode(ret)
            if -1 == ret:
                err_string = "can not get user from source token"
            if -2 == ret:
                err_string = "can not set user to destination token"
            if 1 != ret:
                c.audit['action_detail'] += ", " + err_string
                c.audit['success'] = 0

            Session.commit()
            # Success
            if 1 == ret:
                return sendResult(response, True)
            else:
                return sendError(response, "copying token user failed: %s" % err_string)

        except PolicyException as pe:
            log.exception("[copyTokenUser] Policy Exception %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[copyTokenUser] Error copying token user")
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()

########################################################

    def losttoken(self):
        """
        method:
            admin/losttoken

        description:
            creates a new password token and copies the PIN and the
            user of the old token to the new token.
            The old token is disabled.

        arguments:
            * serial - serial of the old token
            * type   - optional, password, email or sms
            * email  - optional, email address, to overrule the owner email
            * mobile - optional, mobile number, to overrule the owner mobile

        returns:
            a json result with the new serial an the password

        exception:
            if an error occurs an exception is serialized and returned

        """

        ret = 0
        res = {}
        param = {}

        try:
            param.update(request.params)
            serial = param["serial"]

            # check admin authorization
            checkPolicyPre('admin', 'losttoken', param)
            th = TokenHandler()
            res = th.losttoken(serial, param=param)

            c.audit['success'] = ret
            c.audit['serial'] = res.get('serial')
            c.audit['action_detail'] = "from %s" % serial
            c.audit['source_realm'] = getTokenRealms(serial)
            c.audit['realm'] = getTokenRealms(c.audit['serial'])

            Session.commit()
            return sendResult(response, res)

        except PolicyException as pe:
            log.exception("[losttoken] Policy Exception: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[losttoken] Error doing losttoken %r" % e)
            Session.rollback()
            return sendError(response, unicode(e))

        finally:
            Session.close()


########################################################

    def loadtokens(self):
        """
        method:
            admin/loadtokens

        description:
            loads a whole token file to the server

        arguments:
            * file -  the file in a post request
            * type -  the file type.
            * realm - the target real of the tokens

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = "Loading token file failed!"
        known_types = ['aladdin-xml', 'oathcsv', 'yubikeycsv']
        TOKENS = {}
        res = None

        sendResultMethod = sendResult
        sendErrorMethod = sendError

        from linotp.lib.ImportOTP import getKnownTypes
        known_types.extend(getKnownTypes())
        log.info("[loadtokens] importing linotp.lib. Known import types: %s" % known_types)

        from linotp.lib.ImportOTP.PSKC import parsePSKCdata
        log.info("[loadtokens] loaded parsePSKCdata")

        from linotp.lib.ImportOTP.DPWplain import parseDPWdata
        log.info("[loadtokens] loaded parseDPWdata")

        from linotp.lib.ImportOTP.eTokenDat import parse_dat_data
        log.info("[loadtokens] loaded parseDATdata")

        from linotp.lib.ImportOTP.vasco import parseVASCOdata
        log.info("[loadtokens] loaded parseVASCOdata")

        try:
            log.debug("[loadtokens] getting POST request")
            log.debug("[loadtokens] %r" % request.POST)
            tokenFile = request.POST['file']
            fileType = request.POST['type']
            targetRealm = request.POST.get('realm', None)

            # for encrypted token import data, this is the decryption key
            transportkey = request.POST.get('transportkey', None)
            if not transportkey:
                transportkey = None

            pskc_type = None
            pskc_password = None
            pskc_preshared = None
            pskc_checkserial = False

            hashlib = None

            if "pskc" == fileType:
                pskc_type = request.POST['pskc_type']
                pskc_password = request.POST['pskc_password']
                pskc_preshared = request.POST['pskc_preshared']
                if 'pskc_checkserial' in request.POST:
                    pskc_checkserial = True

            fileString = ""
            typeString = ""

            log.debug("[loadtokens] loading token file to server using POST request. Filetype: %s. File: %s"
                        % (fileType, tokenFile))

            # In case of form post requests, it is a "instance" of FieldStorage
            # i.e. the Filename is selected in the browser and the data is transferred
            # in an iframe. see: http://jquery.malsup.com/form/#sample4
            #
            if type(tokenFile).__name__ == 'instance':
                log.debug("[loadtokens] Field storage file: %s", tokenFile)
                fileString = tokenFile.value
                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError
            else:
                fileString = tokenFile
            log.debug("[loadtokens] fileString: %s", fileString)

            if type(fileType).__name__ == 'instance':
                log.debug("[loadtokens] Field storage type: %s", fileType)
                typeString = fileType.value
            else:
                typeString = fileType
            log.debug("[loadtokens] typeString: <<%s>>", typeString)
            if "pskc" == typeString:
                log.debug("[loadtokens] passing password: %s, key: %s, checkserial: %s" % (pskc_password, pskc_preshared, pskc_checkserial))

            if fileString == "" or typeString == "":
                log.error("[loadtokens] file: %s", fileString)
                log.error("[loadtokens] type: %s", typeString)
                log.error("[loadtokens] Error loading/importing token file. file or type empty!")
                return sendErrorMethod(response, "Error loading tokens. File or Type empty!")

            if typeString not in known_types:
                log.error("[loadtokens] Unknown file type: >>%s<<. We only know the types: %s" % (typeString, ', '.join(known_types)))
                return sendErrorMethod(response, "Unknown file type: >>%s<<. We only know the types: %s" % (typeString, ', '.join(known_types)))

            # Parse the tokens from file and get dictionary
            if typeString == "aladdin-xml":
                TOKENS = parseSafeNetXML(fileString)
                # we only do hashlib for aladdin at the moment.
                if 'aladdin_hashlib' in request.POST:
                    hashlib = request.POST['aladdin_hashlib']
            elif typeString == "oathcsv":
                TOKENS = parseOATHcsv(fileString)
            elif typeString == "yubikeycsv":
                TOKENS = parseYubicoCSV(fileString)
            elif typeString == "dpw":
                TOKENS = parseDPWdata(fileString)

            elif typeString == "dat":
                startdate = request.POST.get('startdate', None)
                TOKENS = parse_dat_data(fileString, startdate)

            elif typeString == "feitian":
                TOKENS = parsePSKCdata(fileString, do_feitian=True)
            elif typeString == "pskc":
                if "key" == pskc_type:
                    TOKENS = parsePSKCdata(fileString, preshared_key_hex=pskc_preshared, do_checkserial=pskc_checkserial)
                elif "password" == pskc_type:
                    TOKENS = parsePSKCdata(fileString, password=pskc_password, do_checkserial=pskc_checkserial)
                elif "plain" == pskc_type:
                    TOKENS = parsePSKCdata(fileString, do_checkserial=pskc_checkserial)
            elif typeString == "vasco":
                # TODO: verify merge 2.8.1.2 with 2.9
                vasco_otplen = int(request.POST.get('vasco_otplen', 6))
                TOKENS = parseVASCOdata(fileString, vasco_otplen, transportkey)
                if TOKENS is None:
                    raise ImportException("Vasco DLL was not properly loaded. "
                                          "Importing of VASCO token not "
                                          "possible. Please check the log file"
                                          " for more details.")

            # determin the target realm
            tokenrealm = None
            # default for available realms if no admin policy is defined
            available_realms = getRealms()

            # this needs to return the valid realms of the admin.
            # it also checks the token number
            res = checkPolicyPre('admin', 'import', {})
            if res['realms']:
                # by defualt, wee put the token in the FIRST realm of the admin
                # so tokenrealm will either be ONE realm or NONE
                tokenrealm = res.get('realms')[0]
                available_realms = res.get('realms')

            # if parameter realm is provided, we have to check if this target
            # realm exists and is in the set of the allowed realms
            if targetRealm and targetRealm.lower() in available_realms:
                    tokenrealm = targetRealm
            log.info("[loadtokens] setting tokenrealm %s" % tokenrealm)

            log.debug("[loadtokens] read %i tokens. starting import now"
                      % len(TOKENS))

            # Now import the Tokens from the dictionary
            ret = ""
            th = TokenHandler()
            for serial in TOKENS:
                log.debug("[loadtokens] importing token %s" % TOKENS[serial])

                log.info("[loadtokens] initialize token. serial: %s, realm: %s" % (serial, tokenrealm))

                # # for the eToken dat we assume, that it brings all its
                # # init parameters in correct format
                if typeString == "dat":
                    init_param = TOKENS[serial]

                else:
                    init_param = {
                            'serial': serial,
                            'type': TOKENS[serial]['type'],
                            'description': TOKENS[serial].get("description", "imported"),
                            'otpkey': TOKENS[serial]['hmac_key'],
                            'otplen': TOKENS[serial].get('otplen'),
                            'timeStep': TOKENS[serial].get('timeStep'),
                            'hashlib': TOKENS[serial].get('hashlib')
                            }

                # add additional parameter for vasco tokens
                if TOKENS[serial]['type'] == "vasco":
                    init_param['vasco_appl'] = TOKENS[serial]['tokeninfo'].get('application')
                    init_param['vasco_type'] = TOKENS[serial]['tokeninfo'].get('type')
                    init_param['vasco_auth'] = TOKENS[serial]['tokeninfo'].get('auth')

                # add ocrasuite for ocra tokens, only if ocrasuite is not empty
                if TOKENS[serial]['type'] in ['ocra', 'ocra2']:
                    if TOKENS[serial].get('ocrasuite', "") != "":
                        init_param['ocrasuite'] = TOKENS[serial].get('ocrasuite')

                if hashlib and hashlib != "auto":
                    init_param['hashlib'] = hashlib

                if tokenrealm:
                    checkPolicyPre('admin', 'loadtokens',
                                   {'tokenrealm': tokenrealm})

                (ret, tokenObj) = th.initToken(init_param, User('', '', ''),
                                            tokenrealm=tokenrealm)

                checkPolicyPost('admin', 'loadtokens',
                               {'serial': serial})


            log.info ("[loadtokens] %i tokens imported." % len(TOKENS))
            res = { 'value' : True, 'imported' : len(TOKENS) }

            c.audit['info'] = "%s, %s (imported: %i)" % (fileType, tokenFile, len(TOKENS))
            c.audit['serial'] = ', '.join(TOKENS.keys())
            logTokenNum(c.audit)
            c.audit['success'] = ret
            c.audit['realm'] = tokenrealm

            Session.commit()
            return sendResultMethod(response, res)

        except PolicyException as pe:
            log.exception("[loadtokens] Failed checking policy: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[loadtokens] failed! %r" % e)
            Session.rollback()
            return sendErrorMethod(response, unicode(e))

        finally:
            Session.close()

    def _ldap_parameter_mapping(self, params):
        """
        translate the ui parameters into LDAPResolver format
        """

        # setup the ldap parameters including defaults

        ldap_params = {
            'NOREFERRALS': 'True',
            'CACERTIFICATE': '',
            'EnforceTLS': 'False',
            }

        mapping = {
            "ldap_basedn": 'LDAPBASE',
            "ldap_uri": 'LDAPURI',
            "ldap_binddn": 'BINDDN',
            "ldap_password": "BINDPW",
            "ldap_timeout": 'TIMEOUT',
            "ldap_basedn": 'LDAPBASE',
            "ldap_loginattr": 'LOGINNAMEATTRIBUTE',
            "ldap_searchfilter": 'LDAPSEARCHFILTER',
            "ldap_userfilter": 'LDAPFILTER',
            "ldap_mapping": 'USERINFO',
            "ldap_uidtype": 'UIDTYPE',
            "ldap_sizelimit": 'SIZELIMIT',
            "noreferrals": 'NOREFERRALS',
            "ldap_certificate": 'CACERTIFICATE',
            "enforcetls": 'EnforceTLS',

        }
        for key, value in params.items():
            if key.lower() in mapping:
                ldap_params[mapping[key.lower()]] = value
            else:
                ldap_params[key] = value

        return ldap_params

    def testresolver(self):
        """
        method:
            admin/testresolver

        description:
            This method tests a useridresolvers configuration

        arguments:
            * type     - "LDAP": depending on the type there are other parameters:
                       - "SQL"

            * LDAP:
                * BINDDN
                * BINDPW
                * LDAPURI
                * TIMEOUT
                * LDAPBASE
                * LOGINNAMEATTRIBUTE
                * LDAPSEARCHFILTER
                * LDAPFILTER
                * USERINFO
                * LDAPSEARCHFILTER
                * SIZELIMIT
                * NOREFERRALS
                * CACERTIFICATE

            * SQL:
                * Driver
                * Server
                * Port
                * Database
                * User
                * Password
                * Table

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            request_params = {}
            request_params.update(request.params)

            try:

                typ = request_params["type"]

                # adjust legacy key words, we require the resolver class type

                if typ == 'ldap':
                    typ = 'ldapresolver'

                elif typ in "sql":
                    typ = 'sqlresolver'

                new_resolver_name = request_params["name"]

            except KeyError as exx:
                raise ParameterError(_("Missing parameter: %r") %
                                     exx.message)

            # ---------------------------------------------------------- --

            # this code could be removed, when the webui is adjusted, to
            # use the same parameters as the system/setResolver

            param = request_params
            param['type'] = typ

            if typ == 'ldapresolver':
                param = self._ldap_parameter_mapping(request_params)

            previous_name = param.get('previous_name', '')

            log.debug("[testresolver] testing resolver of type %s" % typ)

            (param, missing,
             _primary_key_changed) = prepare_resolver_parameter(
                                        new_resolver_name=new_resolver_name,
                                        param=param,
                                        previous_name=previous_name)

            if missing:
                raise ParameterError(_("Missing parameter: %r") %
                                     missing)

            # now we can test the connection

            resolver_cls = getResolverClass(param['type'])
            (status, desc) = resolver_cls.testconnection(param)

            res = {
                'result': status,
                'desc': desc
            }

            Session.commit()
            return sendResult(response, res)

        except Exception as e:
            log.exception("[testresolver] failed: %r" % e)
            Session.rollback()
            return sendError(response, unicode(e), 1)

        finally:
            Session.close()

    def checkstatus(self):
        """
        show the status either

        * of one dedicated challenge
        * of all challenges of a token
        * of all challenges belonging to all tokens of a user

        :param transactionid/state:  the transaction id of the challenge
        :param serial: serial number of the token - will show all challenges
        :param user:

        :return: json result of token and challenges

        """
        res = {}
        param = {}


        description = """
            admin/checkstatus: check the token status -
            for assynchronous verification. Missing parameter:
            You need to provide one of the parameters "transactionid", "user" or "serial"'
            """

        try:

            only_open_challenges = True

            param.update(request.params)
            log.debug("[checkstatus] check challenge token status: %r" % param)

            checkPolicyPre('admin', "checkstatus")

            transid = param.get('transactionid', None) or param.get('state', None)
            user = getUserFromParam(param)
            serial = getParam(param, 'serial', optional)
            all = param.get('open', 'False').lower() == 'true'

            if all:
                only_open_challenges = False

            if transid is None and user.is_empty and serial is None:
                # # raise exception
                log.exception("[admin/checkstatus] : missing parameter: "
                             "transactionid, user or serial number for token")
                raise ParameterError("Usage: %s" % description, id=77)

            # # gather all challenges from serial, transactionid and user
            challenges = set()
            if serial is not None:
                challenges.update(Challenges.lookup_challenges(serial=serial,
                                                               filter_open=only_open_challenges))

            if transid is not None:
                challenges.update(Challenges.lookup_challenges(transid=transid,
                                                               filter_open=only_open_challenges))

            # # if we have a user
            if not user.is_empty:
                tokens = getTokens4UserOrSerial(user=user)
                for token in tokens:
                    serial = token.getSerial()
                    challenges.update(
                        Challenges.lookup_challenges(serial=serial,
                                                     filter_open=True))

            serials = set()
            for challenge in challenges:
                serials.add(challenge.getTokenSerial())

            status = {}
            # # sort all information by token serial number
            for serial in serials:
                stat = {}
                chall_dict = {}

                # # add the challenges info to the challenge dict
                for challenge in challenges:
                    if challenge.getTokenSerial() == serial:
                        chall_dict[challenge.getTransactionId()] = \
                                        challenge.get_vars(save=True)
                stat['challenges'] = chall_dict

                # # add the token info to the stat dict
                tokens = getTokens4UserOrSerial(serial=serial)
                token = tokens[0]
                stat['tokeninfo'] = token.get_vars(save=True)

                # # add the local stat to the summary status dict
                status[serial] = stat

            res['values'] = status
            c.audit['success'] = res

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[checkstatus] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe))

        except Exception as exx:
            log.exception("[checkstatus] failed: %r" % exx)
            Session.rollback()
            return sendResult(response, unicode(exx), 0)

        finally:
            Session.close()

    # ------------------------------------------------------------------------ -

    def unpair(self):

        """ admin/unpair - resets a token to its unpaired state """

        try:

            params = dict(**request.params)

            serial = params.get("serial")
            user = getUserFromParam(params)

            # ---------------------------------------------------------------- -

            # check admin authorization

            checkPolicyPre('admin', 'unpair', params, user=user)

            # ---------------------------------------------------------------- -

            tokens = getTokens4UserOrSerial(user, serial)

            if not tokens:
                raise Exception('No token found. Unpairing not possible')

            if len(tokens) > 1:
                raise Exception('Multiple tokens found. Unpairing not possible')

            token = tokens[0]

            # ---------------------------------------------------------------- -

            # prepare some audit entries
            t_owner = token.getUser()

            realms = token.getRealms()
            realm = ''
            if realms:
                realm = realms[0]

            c.audit['user'] = t_owner or ''
            c.audit['realm'] = realm

            # ---------------------------------------------------------------- -

            token.unpair()
            Session.commit()

            # ---------------------------------------------------------------- -

            return sendResult(response, True)

        # -------------------------------------------------------------------- -

        except Exception as exx:
            log.exception("admin/unpair failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0, status=False)

        finally:
            Session.close()


# eof ########################################################################
