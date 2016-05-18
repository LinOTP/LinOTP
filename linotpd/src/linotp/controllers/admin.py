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

"""
admin controller - interfaces to administrate LinOTP
"""



import logging

from pylons import request, response, config, tmpl_context as c
import json

from linotp.lib.base import BaseController

from linotp.lib.token import enableToken, assignToken , unassignToken, removeToken
from linotp.lib.token import setPin, setMaxFailCount, setOtpLen, setSyncWindow, setCounterWindow
from linotp.lib.token import setDescription
from linotp.lib.token import resyncToken, resetToken, setPinUser, setPinSo, setHashLib, addTokenInfo
from linotp.lib.token import TokenIterator, initToken, setRealms, getTokenType, get_serial_by_otp
from linotp.lib.token import getTokens4UserOrSerial, copyTokenPin, copyTokenUser, losttoken, check_serial
from linotp.lib.token import genSerial
from linotp.lib.token import (newToken,
                              getTokenOwner
                              )

from linotp.lib.error import ParameterError
from linotp.lib.util import getParam, getLowerParams
from linotp.lib.util import check_session, SESSION_KEY_LENGTH, remove_session_from_param
from linotp.lib.util import get_client
from linotp.lib.user import (getSearchFields,
                             getUserList,
                             getUserListIterators,
                             User,
                             getUserFromParam,
                             getUserFromRequest
                             )


from linotp.lib.realm import getDefaultRealm, getRealms

from linotp.lib.reply import (sendResult,
                              sendError,
                              sendXMLResult,
                              sendXMLError,
                              sendCSVResult,
                              sendResultIterator,
                              )
from linotp.lib.reply import sendQRImageResult

from linotp.lib.validate import get_challenges

from linotp.model.meta import Session
from linotp.lib.policy import checkPolicyPre, checkPolicyPost, PolicyException, getAdminPolicies, getOTPPINEncrypt
from linotp.lib.audit.base import logTokenNum
# for loading XML file
from linotp.lib.ImportOTP import parseSafeNetXML, parseOATHcsv, ImportException, parseYubicoCSV


from tempfile import mkstemp
import os


# For logout
from webob.exc import HTTPUnauthorized

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
            log.debug("[__before__::%r] %r" % (action, params))

            audit.initialize()
            c.audit['success'] = False
            c.audit['client'] = get_client()
            # Session handling
            check_session()

            return request

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

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

            audit.log(c.audit)
            Session.commit()
            return request

        except Exception as e:
            log.exception("[__after__] unable to create a session cookie: %r" % e)
            Session.rollback()
            return sendError(response, e, context='after')

        finally:
            Session.close()
            log.debug("[__after__] done")


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
            log.debug("[getsession] done")

    def dropsession(self):
        # request.cookies.pop( 'admin_session', None )
        # FIXME: Does not seem to work
        response.set_cookie('admin_session', None, expires=1)
        return

    def getTokenOwner(self):
        """
        provide the userinfo of the token, which is specified as serial
        """
        log.debug("get the owner as user info for a token")

        param = {}
        ret = {}
        try:
            param.update(request.params)
            serial = param["serial"]

            # check admin authorization
            checkPolicyPre('admin', 'tokenowner', param)

            owner = getTokenOwner(serial)
            if owner.info:
                ret = owner.info

            c.audit['success'] = len(ret) > 0

            Session.commit()
            return sendResult(response, ret)

        except PolicyException as pe:
            log.exception("policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("failed: %r" % e)
            Session.rollback()
            log.error('error getting token owner')
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[enable] done')

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

            user = getUserFromParam(param, optional)

            filterRealm = []
            # check admin authorization
            res = checkPolicyPre('admin', 'show', param, user=user)

            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            filterRealm = ['*']
            if res['active'] and res['realms']:
                filterRealm = res['realms']

            if realm:
                # If the admin wants to see only one realm, then do it:
                log.debug("[show] checking to only see tokens in realm <%s>",
                          realm)
                if realm in filterRealm or '*' in filterRealm:
                    filterRealm = [realm]

            log.info("[show] admin >%s< may display the following realms: %r",
                     res['admin'], filterRealm)
            log.info("[show] displaying tokens: serial: %s, page: %s, "
                     "filter: %s, user: %s", serial, page, filter, user.login)

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
                log.debug("tokenline: %s" % tok)
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
            log.debug("[show] done")


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
        log.debug("[remove] calling remove ")

        param = request.params

        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)

            # check admin authorization
            checkPolicyPre('admin', 'remove', param)

            log.info("[remove] removing token with serial %s for user %s", serial, user.login)
            ret = removeToken(user, serial)

            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm'] and "" != c.audit['user']:
                c.audit['realm'] = getDefaultRealm()
            logTokenNum()
            c.audit['success'] = ret

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.isEmpty():
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
            log.debug('[remove] done')


########################################################
    def enable (self):
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
        log.debug("[enable] calling enable to enable/disable a token")

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)

            # check admin authorization
            checkPolicyPre('admin', 'enable', param , user=user)

            log.info("[enable] enable token with serial %s for user %s@%s.", serial, user.login, user.realm)
            ret = enableToken(True, user, serial)

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            logTokenNum()

            if "" == c.audit['realm'] and "" != c.audit['user']:
                c.audit['realm'] = getDefaultRealm()

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.isEmpty():
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
            log.debug('[enable] done')


########################################################
    def getSerialByOtp (self):
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
        log.debug("[getSerialByOtp] entering function")

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

            serial, username, resolverClass = get_serial_by_otp(None, otp, 10, typ=typ, realm=realm, assigned=assigned)
            log.debug("[getSerialByOtp] found %s with user %s" % (serial, username))

            if "" != serial:
                checkPolicyPost('admin', 'getserial', {'serial' : serial})

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
            log.debug("[getSerialByOtp] done")


########################################################
    def disable (self):
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
        log.debug("calling enable to enable/disable a token")

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)

            # check admin authorization
            checkPolicyPre('admin', 'disable', param, user=user)

            log.info("[disable] disable token with serial %s for user %s@%s.", serial, user.login, user.realm)
            ret = enableToken(False, user, serial)

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm'] and "" != c.audit['user']:
                c.audit['realm'] = getDefaultRealm()

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.isEmpty():
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
            log.debug('[disable] done')


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
        log.debug("calling check_serial")

        param = request.params
        try:
            serial = getParam(param, "serial", required)

            # check admin authorization
            # try:
            #    checkPolicyPre('admin', 'disable', param )
            # except PolicyException as pe:
            #    return sendError(response, str(pe), 1)

            log.info("[check_serial] checking serial %s" % serial)
            (unique, new_serial) = check_serial(serial)

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
            log.debug("[check_serial] done")


########################################################
    def init(self):
        """
        method:
            admin/init

        description:
            creates a new token.

        arguments:
            * otpkey    - required - the hmac Key of the token
            * genkey    - required - =1, if key should be generated. We either need otpkey or genkey
            * keysize   - optional - either 20 or 32. Default is 20
            * serial    - required - the serial number / identifier of the token
            * description - optional
            * pin        - optional - the pin of the user pass
            * user       - optional - login user name
            * realm      - optional - realm of the user
            * type       - optional - the type of the token
            * tokenrealm - optional - the realm a token should be put into
            * otplen     - optional  - length of the OTP value
            * hashlib    - optional  - used hashlib sha1 oder sha256

        ocra arguments:
            for generating OCRA Tokens type=ocra you can specify the following parameters:

            * ocrasuite    - optional - if you do not want to use the default ocra suite OCRA-1:HOTP-SHA256-8:QA64
            * sharedsecret - optional - if you are in Step0 of enrolling an OCRA/QR token the
              sharedsecret=1 specifies,
              that you want to generate a shared secret
            * activationcode - optional - if you are in Step1 of enrolling an OCRA token you need to pass the
              activation code, that was generated in the QRTAN-App

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        log.debug("[init] calling the init controller function")
        ret = False
        response_detail = {}
        helper_param = {}

        try:
            tokenrealm = None
            param = request.params
            helper_param.update(param)

            user = getUserFromParam(param, optional)

            # check admin authorization
            res = checkPolicyPre('admin', 'init', param, user=user)

            if user is not None:
                helper_param['user.login'] = user.login
                helper_param['user.realm'] = user.realm

            # # for genkey, we have to transfer this to the lowest level
            key_size = getParam(param, "keysize", optional) or 20
            helper_param['key_size'] = key_size

            tok_type = getParam(param, "type", optional) or 'hmac'

            # if no user is given, we put the token in all realms of the admin
            if user.login == "":
                log.debug("[init] setting tokenrealm %s" % res['realms'])
                tokenrealm = res['realms']


            # # look for the tokenclass to support a class init
            # # the classInit could do a rewrite of the request parameters
            # # which are then used in the tokenInit as parameters
            # # this is for example
            # #   to find all open init challenges of a token type and set the
            # #   serial number in the parameter list

            g = config['pylons.app_globals']
            tokenclasses = g.tokenclasses

            tokenTypes = tokenclasses.keys()
            if tok_type in tokenTypes:
                tclass = tokenclasses.get(tok_type)
                tclass_object = newToken(tclass)
                if hasattr(tclass_object, 'classInit'):
                    h_params = tclass_object.classInit(param, user=user)
                    helper_param.update(h_params)


            serial = helper_param.get('serial', None)
            prefix = helper_param.get('prefix', None)
            if not serial:
                serial = genSerial(tok_type, prefix)

            helper_param['serial'] = serial

            log.info("[init] initialize token. user: %s, serial: %s" % (user.login, serial))
            (ret, tokenObj) = initToken(helper_param, user, tokenrealm=tokenrealm)

            # # result enrichment - if the token is sucessfully created,
            # # some processing info is added to the result document,
            # #  e.g. the otpkey :-) as qr code
            initDetail = tokenObj.getInitDetail(helper_param, user)
            response_detail.update(initDetail)

            if tokenObj is not None and ret is True:
                c.audit['serial'] = tokenObj.getSerial()
                c.audit['token_type'] = tokenObj.type

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm

            # DeleteMe: This code will never run, since getUserFromParam
            # always returns a realm!
            # if "" == c.audit['realm'] and "" != c.audit['user']:
            #    c.audit['realm'] = getDefaultRealm()

            logTokenNum()
            c.audit['success'] = ret
            checkPolicyPost('admin', 'init', helper_param, user=user)

            Session.commit()

            # # finally we render the info as qr immage, if the qr parameter
            # # is provided and if the token supports this
            if 'qr' in param and tokenObj is not None:
                (rdata, hparam) = tokenObj.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam['qr'] = param.get('qr') or 'html'
                return sendQRImageResult(response, rdata, hparam)
            else:
                return sendResult(response, ret, opt=response_detail)

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
            log.debug('[init] done')


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
        log.debug("[unassign] entering function unassign")

        param = request.params

        try:

            serial = getParam(param, "serial", required)
            user = getUserFromParam(param, optional)

            log.debug("[unassign] unassigning serial %r, user %r" % (serial, user))

            # check admin authorization
            checkPolicyPre('admin', 'unassign', param)

            log.info("[unassign] unassigning token with serial %r from "
                     "user %r@%r" % (serial, user.login, user.realm))
            ret = unassignToken(serial, user, None)

            c.audit['success'] = ret
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm']:
                c.audit['realm'] = getDefaultRealm()

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict['message'] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.isEmpty():
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
            log.debug('[unassign] done')


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
        log.debug("[assign] entering function assign")

        param = request.params

        try:

            upin = getParam(param, "pin", optional)
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)

            # check admin authorization
            checkPolicyPre('admin', 'assign', param)

            log.info("[assign] assigning token with serial %s to user %s@%s" % (serial, user.login, user.realm))
            res = assignToken(serial, user, upin, param)

            checkPolicyPost('admin', 'assign', param, user)

            c.audit['success'] = res
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm
            if "" == c.audit['realm']:
                c.audit['realm'] = getDefaultRealm()

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception('[assign] policy failed %r' % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e :
            log.exception('[assign] token assignment failed! %r' % e)
            Session.rollback()
            return sendError(response, e, 0)

        finally:
            Session.close()
            log.debug('[setPin] done')


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
        log.debug('[setPin]')
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

            if count == 0 :
                Session.rollback()
                return sendError(response, ParameterError("Usage: %s" % description, id=77))

            c.audit['success'] = count

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception('[setPin] policy failed %r, %r' % (msg, pe))
            Session.rollback()
            return sendError(response, unicode(pe), 1)


        except Exception as e :
            log.exception('[setPin] %s :%r' % (msg, e))
            Session.rollback()
            return sendError(response, unicode(e), 0)

        finally:
            Session.close()
            log.debug('[setPin] done')



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
        log.debug("[set]")

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
        log.debug('[set]')
        msg = ""

        try:
            param = getLowerParams(request.params)

            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)

            # check admin authorization
            checkPolicyPre('admin', 'set', param, user=user)

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

            if param.has_key("MaxFailCount".lower()):
                msg = "[set] setting MaxFailCount failed"
                maxFail = int(getParam(param, "MaxFailCount".lower(), required))
                log.info("[set] setting maxFailCount (%r) for token with serial %r" % (maxFail, serial))
                ret = setMaxFailCount(maxFail, user, serial)
                res["set MaxFailCount"] = ret
                count = count + 1
                c.audit['action_detail'] += "maxFailCount=%d, " % maxFail

            if param.has_key("SyncWindow".lower()):
                msg = "[set] setting SyncWindow failed"
                syncWindow = int(getParam(param, "SyncWindow".lower(), required))
                log.info("[set] setting syncWindow (%r) for token with serial %r" % (syncWindow, serial))
                ret = setSyncWindow(syncWindow, user, serial)
                res["set SyncWindow"] = ret
                count = count + 1
                c.audit['action_detail'] += "syncWindow=%d, " % syncWindow

            if param.has_key("description".lower()):
                msg = "[set] setting description failed"
                description = getParam(param, "description".lower(), required)
                log.info("[set] setting description (%r) for token with serial %r" % (description, serial))
                ret = setDescription(description, user, serial)
                res["set description"] = ret
                count = count + 1
                c.audit['action_detail'] += "description=%r, " % description

            if param.has_key("CounterWindow".lower()):
                msg = "[set] setting CounterWindow failed"
                counterWindow = int(getParam(param, "CounterWindow".lower(), required))
                log.info("[set] setting counterWindow (%r) for token with serial %r" % (counterWindow, serial))
                ret = setCounterWindow(counterWindow, user, serial)
                res["set CounterWindow"] = ret
                count = count + 1
                c.audit['action_detail'] += "counterWindow=%d, " % counterWindow

            if param.has_key("OtpLen".lower()):
                msg = "[set] setting OtpLen failed"
                otpLen = int(getParam(param, "OtpLen".lower(), required))
                log.info("[set] setting OtpLen (%r) for token with serial %r" % (otpLen, serial))
                ret = setOtpLen(otpLen, user, serial)
                res["set OtpLen"] = ret
                count = count + 1
                c.audit['action_detail'] += "otpLen=%d, " % otpLen

            if param.has_key("hashlib".lower()):
                msg = "[set] setting hashlib failed"
                hashlib = getParam(param, "hashlib".lower(), required)
                log.info("[set] setting hashlib (%r) for token with serial %r" % (hashlib, serial))
                ret = setHashLib(hashlib, user, serial)
                res["set hashlib"] = ret
                count = count + 1
                c.audit['action_detail'] += "hashlib=%s, " % unicode(hashlib)

            if param.has_key("timeWindow".lower()):
                msg = "[set] setting timeWindow failed"
                timeWindow = int(getParam(param, "timeWindow".lower(), required))
                log.info("[set] setting timeWindow (%r) for token with serial %r" % (timeWindow, serial))
                ret = addTokenInfo("timeWindow", timeWindow , user, serial)
                res["set timeWindow"] = ret
                count = count + 1
                c.audit['action_detail'] += "timeWindow=%d, " % timeWindow

            if param.has_key("timeStep".lower()):
                msg = "[set] setting timeStep failed"
                timeStep = int(getParam(param, "timeStep".lower(), required))
                log.info("[set] setting timeStep (%r) for token with serial %r" % (timeStep, serial))
                ret = addTokenInfo("timeStep", timeStep , user, serial)
                res["set timeStep"] = ret
                count = count + 1
                c.audit['action_detail'] += "timeStep=%d, " % timeStep

            if param.has_key("timeShift".lower()):
                msg = "[set] setting timeShift failed"
                timeShift = int(getParam(param, "timeShift".lower(), required))
                log.info("[set] setting timeShift (%r) for token with serial %r" % (timeShift, serial))
                ret = addTokenInfo("timeShift", timeShift , user, serial)
                res["set timeShift"] = ret
                count = count + 1
                c.audit['action_detail'] += "timeShift=%d, " % timeShift

            if param.has_key("countAuth".lower()):
                msg = "[set] setting countAuth failed"
                ca = int(getParam(param, "countAuth".lower(), required))
                log.info("[set] setting count_auth (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.set_count_auth(int(ca))
                    count = count + 1
                    ret += 1
                res["set countAuth"] = ret
                c.audit['action_detail'] += "countAuth=%d, " % ca

            if param.has_key("countAuthMax".lower()):
                msg = "[set] setting countAuthMax failed"
                ca = int(getParam(param, "countAuthMax".lower(), required))
                log.info("[set] setting count_auth_max (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.set_count_auth_max(int(ca))
                    count = count + 1
                    ret += 1
                res["set countAuthMax"] = ret
                c.audit['action_detail'] += "countAuthMax=%d, " % ca

            if param.has_key("countAuthSuccess".lower()):
                msg = "[set] setting countAuthSuccess failed"
                ca = int(getParam(param, "countAuthSuccess".lower(), required))
                log.info("[set] setting count_auth_success (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.set_count_auth_success(int(ca))
                    count = count + 1
                    ret += 1
                res["set countAuthSuccess"] = ret
                c.audit['action_detail'] += "countAuthSuccess=%d, " % ca

            if param.has_key("countAuthSuccessMax".lower()):
                msg = "[set] setting countAuthSuccessMax failed"
                ca = int(getParam(param, "countAuthSuccessMax".lower(), required))
                log.info("[set] setting count_auth_success_max (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.set_count_auth_success_max(int(ca))
                    count = count + 1
                    ret += 1
                res["set countAuthSuccessMax"] = ret
                c.audit['action_detail'] += "countAuthSuccessMax=%d, " % ca

            if param.has_key("validityPeriodStart".lower()):
                msg = "[set] setting validityPeriodStart failed"
                ca = getParam(param, "validityPeriodStart".lower(), required)
                log.info("[set] setting validity_period_start (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.set_validity_period_start(ca)
                    count = count + 1
                    ret += 1
                res["set validityPeriodStart"] = ret
                c.audit['action_detail'] += u"validityPeriodStart=%s, " % unicode(ca)

            if param.has_key("validityPeriodEnd".lower()):
                msg = "[set] setting validityPeriodEnd failed"
                ca = getParam(param, "validityPeriodEnd".lower(), required)
                log.info("[set] setting validity_period_end (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.set_validity_period_end(ca)
                    count = count + 1
                    ret += 1
                res["set validityPeriodEnd"] = ret
                c.audit['action_detail'] += "validityPeriodEnd=%s, " % unicode(ca)

            if "phone" in param:
                msg = "[set] setting phone failed"
                ca = getParam(param, "phone".lower(), required)
                log.info("[set] setting phone (%r) for token with serial %r" % (ca, serial))
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.addToTokenInfo("phone", ca)
                    count = count + 1
                    ret += 1
                res["set phone"] = ret
                c.audit['action_detail'] += "phone=%s, " % unicode(ca)

            if count == 0 :
                Session.rollback()
                return sendError(response, ParameterError("Usage: %s" % description, id=77))

            c.audit['success'] = count
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm

            # DeleteMe: This code will never run, since getUserFromParam
            # always returns a realm!
            # if "" == c.audit['realm'] and "" != c.audit['user']:
            #    c.audit['realm'] = getDefaultRealm()
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
            log.debug('[set] done')


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
        log.debug("[resync]")

        param = request.params
        try:
            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)

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

            log.info("[resync] resyncing token with serial %r, user %r@%r"
                     % (serial, user.login, user.realm))
            res = resyncToken(otp1, otp2, user, serial, options)

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
            log.debug('[resync] done')


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
        param = request.params

        # check admin authorization
        # check if we got a realm or resolver, that is ok!
        try:
            realm = getParam(param, "realm", optional)
            checkPolicyPre('admin', 'userlist', param)

            up = 0
            user = getUserFromParam(param, optional)

            log.info("[userlist] displaying users with param: %s, ", param)

            if (len(user.realm) > 0):
                up = up + 1
            if (len(user.conf) > 0):
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
            log.debug("[userlist] done")


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
        log.debug("[tokenrealm] calling tokenrealm")

        param = request.params
        try:
            serial = getParam(param, "serial", required)
            realms = getParam(param, "realms", required)

            # check admin authorization
            checkPolicyPre('admin', 'tokenrealm', param)

            log.info("[tokenrealm] setting realms for token %s to %s" % (serial, realms))
            realmList = realms.split(',')
            ret = setRealms(serial, realmList)

            c.audit['success'] = ret
            c.audit['info'] = realms

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
            log.debug("[tokenrealm] done")


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
        log.debug("[reset]")

        param = request.params

        serial = getParam(param, "serial", optional)
        user = getUserFromParam(param, optional)

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
            elif ret == 0 and user and not user.isEmpty():
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
            log.debug("[reset] done")


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
        log.debug("[copyTokenPin]")
        ret = 0
        err_string = ""
        param = request.params

        try:
            serial_from = getParam(param, "from", required)
            serial_to = getParam(param, "to", required)

            # check admin authorization
            checkPolicyPre('admin', 'copytokenpin', param)

            log.info("[copyTokenPin] copying Pin from token %s to token %s" % (serial_from, serial_to))
            ret = copyTokenPin(serial_from, serial_to)

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
        log.debug("[copyTokenUser]")
        ret = 0
        err_string = ""
        param = request.params

        try:

            serial_from = getParam(param, "from", required)
            serial_to = getParam(param, "to", required)

            # check admin authorization
            checkPolicyPre('admin', 'copytokenuser', param)

            log.info("[copyTokenUser] copying User from token %s to token %s" % (serial_from, serial_to))
            ret = copyTokenUser(serial_from, serial_to)

            c.audit['success'] = ret
            c.audit['serial'] = serial_to
            c.audit['action_detail'] = "from %s" % serial_from

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
            log.exception("[losttoken] Error doing losttoken %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[copyTokenUser] Error copying token user")
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug('[copyTokenUser] done')

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
        log.debug("[losttoken]")

        ret = 0
        res = {}
        param = {}

        try:
            param.update(request.params)
            serial = param["serial"]

            # check admin authorization
            checkPolicyPre('admin', 'losttoken', param)

            res = losttoken(serial, param=param)

            c.audit['success'] = ret
            c.audit['serial'] = res.get('serial')
            c.audit['action_detail'] = "from %s" % serial

            Session.commit()
            return sendResult(response, res)

        except PolicyException as pe:
            log.exception("[losttoken] Error doing losttoken %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[losttoken] Error doing losttoken %r" % e)
            Session.rollback()
            return sendError(response, unicode(e))

        finally:
            Session.close()
            log.debug('[losttoken] done')


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
        log.debug("[loadtokens]")
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
                    # log.debug(TOKENS)
                elif "plain" == pskc_type:
                    TOKENS = parsePSKCdata(fileString, do_checkserial=pskc_checkserial)
            elif typeString == "vasco":
                vasco_otplen = request.POST['vasco_otplen']
                (fh, filename) = mkstemp()
                f = open(filename, "w")
                f.write(fileString)
                f.close()
                TOKENS = parseVASCOdata(filename, int(vasco_otplen))
                os.remove(filename)
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

                (ret, tokenObj) = initToken(init_param, User('', '', ''),
                                            tokenrealm=tokenrealm)

                checkPolicyPost('admin', 'loadtokens',
                               {'serial': serial})


            log.info ("[loadtokens] %i tokens imported." % len(TOKENS))
            res = { 'value' : True, 'imported' : len(TOKENS) }

            c.audit['info'] = "%s, %s (imported: %i)" % (fileType, tokenFile, len(TOKENS))
            c.audit['serial'] = ', '.join(TOKENS.keys())
            logTokenNum()
            c.audit['success'] = ret

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
            log.debug('[loadtokens] done')


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
        res = {}

        try:
            param = getLowerParams(request.params)

            typ = getParam(param, "type", required)
            log.debug("[testresolver] testing resolver of type %s" % typ)

            if typ == "ldap":
                import useridresolver.LDAPIdResolver

                param['BINDDN'] = getParam(param, "ldap_binddn", required)
                param['BINDPW'] = getParam(param, "ldap_password", required)
                param['LDAPURI'] = getParam(param, "ldap_uri", required)
                param['TIMEOUT'] = getParam(param, "ldap_timeout", required)
                param['LDAPBASE'] = getParam(param, "ldap_basedn", required)
                param['LOGINNAMEATTRIBUTE'] = getParam(param, "ldap_loginattr", required)
                param['LDAPSEARCHFILTER'] = getParam(param, "ldap_searchfilter", required)
                param['LDAPFILTER'] = getParam(param, "ldap_userfilter", required)
                param['USERINFO'] = getParam(param, "ldap_mapping", required)
                param['SIZELIMIT'] = getParam(param, "ldap_sizelimit", required)
                param['NOREFERRALS'] = getParam(param, "noreferrals", optional)
                param['CACERTIFICATE'] = getParam(param, "ldap_certificate", optional)

                (status, desc) = useridresolver.LDAPIdResolver.IdResolver.testconnection(param)
                res['result'] = status
                res['desc'] = desc

            elif typ == "sql":
                import useridresolver.SQLIdResolver

                param["Driver"] = getParam(param, "sql_driver", required)
                param["Server"] = getParam(param, "sql_server", required)
                param["Port"] = getParam(param, "sql_port", required)
                param["Database"] = getParam(param, "sql_database", required)
                param["User"] = getParam(param, "sql_user", required)
                param["Password"] = getParam(param, "sql_password", required)
                param["Table"] = getParam(param, "sql_table", required)
                param["Where"] = getParam(param, "sql_where", optional)
                param["ConnectionParams"] = getParam(param, "sql_conparams", optional)

                (num, err_str) = useridresolver.SQLIdResolver.testconnection(param)
                res['result'] = True
                res['rows'] = num
                res['err_string'] = err_str

            Session.commit()
            return sendResult(response, res)

        except Exception as e:
            log.exception("[testresolver] failed: %r" % e)
            Session.rollback()
            return sendError(response, unicode(e), 1)

        finally:
            Session.close()
            log.debug('[testresolver] done')


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

            param.update(request.params)
            log.debug("[checkstatus] check challenge token status: %r" % param)

            checkPolicyPre('admin', "checkstatus")

            transid = param.get('transactionid', None) or param.get('state', None)
            user = getUserFromParam(param, optional)
            serial = getParam(param, 'serial'          , optional)

            if transid is None and user.isEmpty() and serial is None:
                # # raise exception
                log.exception("[admin/checkstatus] : missing parameter: "
                             "transactionid, user or serial number for token")
                raise ParameterError("Usage: %s" % description, id=77)

            # # gather all challenges from serial, transactionid and user
            challenges = set()
            if serial is not None:
                challenges.update(get_challenges(serial=serial))

            if transid is not None :
                challenges.update(get_challenges(transid=transid))

            # # if we have a user
            if user.isEmpty() == False:
                tokens = getTokens4UserOrSerial(user=user)
                for token in tokens:
                    serial = token.getSerial()
                    challenges.update(get_challenges(serial=serial))

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
                        chall_dict[challenge.getTransactionId()] = challenge.get_vars(save=True)
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
            log.debug('[ocra/checkstatus] done')


def iterate_users(user_iterators):
    """
    build a userlist iterator / generator that returns the user data on demand

    :param user_iterators: list of tuple (userlist iterators, resolver descr)
    :return: generator of user data dicts (yield)
    """

    for itera in user_iterators:
        user_iterator = itera[0]
        reso = itera[1]
        log.debug("iterating: %r" % reso)

        try:
            while True:
                user_data = user_iterator.next()
                if type(user_data) in [list]:
                    for data in user_data:
                        data['resolver'] = reso
                        resp = "%s" % json.dumps(data)
                        yield resp
                else:
                    user_data['resolver'] = reso
                    resp = "%s" % json.dumps(user_data)
                    yield resp
        except StopIteration as exx:
            # pass on to next iterator
            pass
        except Exception as exx:
            log.exception("Problem during iteration of userlist iterators: %r"
                       % exx)

    raise StopIteration()

#eof###########################################################################
