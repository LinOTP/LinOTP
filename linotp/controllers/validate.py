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
validate controller - to check the authentication request
"""

import logging

from flask import current_app, g
from flask_babel import gettext as _

from linotp import flap
from linotp.flap import (
    request, response, config,
    tmpl_context as c, abort
)

from linotp.lib.auth.validate import ValidationHandler
from linotp.controllers.base import BaseController
from linotp.lib.config import getFromConfig
from linotp.lib.error import ParameterError

from linotp.lib.policy import AuthorizeException
from linotp.lib.policy import check_auth_serial
from linotp.lib.policy import check_auth_tokentype
from linotp.lib.policy import check_user_authorization
from linotp.lib.policy import is_auth_return
from linotp.lib.policy import set_realm

from linotp.lib.realm import getDefaultRealm
from linotp.lib.reply import sendQRImageResult
from linotp.lib.reply import sendResult, sendError
from linotp.lib.token import getTokens4UserOrSerial
from linotp.lib.token import get_tokenserial_of_transaction
from linotp.tokens.base import TokenClass

from linotp.lib.user import User
from linotp.lib.user import getUserFromParam
from linotp.lib.user import getUserId
from linotp.lib.user import getUserInfo
from linotp.lib.util import get_client

from linotp.lib.context import request_context
from linotp.lib.error import ValidateError
from linotp.lib.pairing import decrypt_pairing_response

from linotp.model import db

CONTENT_TYPE_PAIRING = 1

log = logging.getLogger(__name__)


class ValidateController(BaseController):

    '''
    The linotp.controllers are the implementation of the web-API to talk to the LinOTP server.
    The ValidateController is used to validate the username with its given OTP value.
    An Authentication module like pam_linotp2 or rlm_linotp2 uses this ValidateController.
    The functions of the ValidateController are invoked like this

        https://server/validate/<functionname>

    The functions are described below in more detail.
    '''

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError
        """

        action = request_context['action']

        try:
            g.audit['client'] = get_client(request)

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            db.session.rollback()
            return sendError(response, exx, context='before')


    @staticmethod
    def __after__(response):
        '''
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        '''

        current_app.audit_obj.log(g.audit)
        return response


    def _check(self, param):
        '''
        basic check function, that can be used by different controllers

        :param param: dict of all caller parameters
        :type param: dict

        :return: Tuple of True or False and opt
        :rtype: Tuple(boolean, opt)

        '''
        opt = None

        options = {}

        # put everything in the options but the user, pass, init
        options.update(param)
        for para in ["pass", "user", "init"]:
            if para in options:
                del options[para]

        passw = param.get("pass")
        user = getUserFromParam(param)

        # support for challenge verification
        challenge = param.get("challenge")
        if challenge is not None:
            options = {}
            options['challenge'] = challenge

        g.audit['user'] = user.login
        realm = user.realm or getDefaultRealm()
        g.audit['realm'] = realm

        # AUTHORIZATION Pre Check
        # we need to overwrite the user.realm in case the
        # user does not exist in the original realm (setrealm-policy)
        user.realm = set_realm(user.login, realm, exception=True)
        check_user_authorization(user.login, user.realm, exception=True)

        vh = ValidationHandler()
        (ok, opt) = vh.checkUserPass(user, passw, options=options)

        g.audit.update(request_context.get('audit', {}))
        g.audit['success'] = ok

        if ok:
            # AUTHORIZATION post check
            check_auth_tokentype(g.audit['serial'], exception=True, user=user)
            check_auth_serial(g.audit['serial'], exception=True, user=user)

        # add additional details
        if is_auth_return(ok, user=user):
            if opt is None:
                opt = {}
            if ok:
                opt['realm'] = g.audit.get('realm')
                opt['user'] = g.audit.get('user')
                opt['tokentype'] = g.audit.get('token_type')
                opt['serial'] = g.audit.get('serial')
            else:
                opt['error'] = g.audit.get('action_detail')

        return (ok, opt)


    # @profile_decorator(log_file="/tmp/validate.prof")
    def check(self):

        '''
        This function is used to validate the username and the otp value/password.

        method:
            validate/check

        arguments:

           * user: The username or loginname
           * pass: The password that consist of a possible fixed password component and the OTP value
           * realm (optional): The realm to be used to match the user to a useridresolver
           * challenge (optional): This param indicates, that this request is a challenge request.
           * data (optional): Data to use to generate a challenge
           * state (optional): A state id of an existing challenge to respond to
           * transactionid (optional): A transaction id of an existing challenge to respond to
           * serial (optional): Serial of a token to use instead of the matching tokens found for the given user and pass

        returns:
            JSON response::

                {
                    "version": "LinOTP 2.4",
                    "jsonrpc": "2.0",
                    "result": {
                        "status": true,
                        "value": false
                    },
                    "id": 0
                }

            If ``status`` is ``true`` the request was handled successfully.

            If ``value`` is ``true`` the user was authenticated successfully.
        '''

        param = self.request_params.copy()
        ok = False
        opt = None

        try:
            # prevent the detection if a user exist
            # by sending a request w.o. pass parameter
            try:
                (ok, opt) = self._check(param)
            except (AuthorizeException, ParameterError) as exx:
                log.warning("[check] authorization failed for validate/check: %r"
                            % exx)
                g.audit['success'] = False
                g.audit['info'] = str(exx)
                ok = False
                if is_auth_return(ok):
                    if opt is None:
                        opt = {}
                    opt['error'] = g.audit.get('info')

            db.session.commit()

            qr = param.get('qr', None)
            if qr and opt and 'message' in opt:
                try:
                    dataobj = opt.get('message')
                    param['alt'] = "%s" % opt
                    if 'transactionid' in opt:
                        param['transactionid'] = opt['transactionid']
                    return sendQRImageResult(response, dataobj, param)
                except Exception as exc:
                    log.warning("failed to send QRImage: %r " % exc)
                    return sendQRImageResult(response, opt, param)
            else:
                return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("[check] validate/check failed: %r" % exx)
            # If an internal error occurs or the SMS gateway did not send the SMS, we write this to the detail info.
            g.audit['info'] = "%r" % exx
            db.session.rollback()
            return sendResult(response, False, 0)

        finally:
            db.session.close()

    def check_status(self):
        """
        check the status of a transaction - for polling support
        """

        try:

            param = self.request_params

            #
            # we require either state or transactionid as parameter

            transid = param.get('state', param.get('transactionid', None))
            if not transid:
                raise ParameterError(_('Missing required parameter "state" or '
                                     '"transactionid"!'))

            #
            # serial is an optional parameter

            serial = param.get('serial', None)

            # user is an optional parameter:
            # if no 'user' in the parameters, the User object will be empty
            user = getUserFromParam(param)

            passw = param.get('pass')
            if passw is None:
                raise ParameterError(_('Missing required parameter "pass"!'))

            use_offline = param.get('use_offline', False)

            va = ValidationHandler()
            ok, opt = va.check_status(transid=transid, user=user,
                                      serial=serial, password=passw,
                                      use_offline=use_offline)

            g.audit['success'] = ok
            g.audit['info'] = str(opt)

            db.session.commit()
            return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("check_status failed: %r" % exx)
            g.audit['info'] = str(exx)
            db.session.rollback()
            return sendResult(response, False, 0)

    def check_yubikey(self):
        '''
        This function is used to validate the output of a yubikey

        method:
            validate/check_yubikey

        :param pass: The password that consist of the static yubikey prefix and the otp
        :type pass: string

        :return: JSON Object

        returns:
            JSON response::

                {
                    "version": "LinOTP 2.4",
                    "jsonrpc": "2.0",
                    "result": {
                        "status": true,
                        "value": false
                    },
                    "detail" : {
                        "username": username,
                        "realm": realm
                    },
                    "id": 0
                }
        '''

        try:

            try:
                passw = self.request_params['pass']
            except KeyError:
                raise ParameterError("Missing parameter: 'pass'")

            ok = False
            try:
                vh = ValidationHandler()
                ok, opt = vh.checkYubikeyPass(passw)
                g.audit['success'] = ok

            except AuthorizeException as exx:
                log.warning("[check_yubikey] authorization failed for validate/check_yubikey: %r"
                            % exx)
                g.audit['success'] = False
                g.audit['info'] = str(exx)
                ok = False

            db.session.commit()
            return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("[check_yubikey] validate/check_yubikey failed: %r" % exx)
            g.audit['info'] = str(exx)
            db.session.rollback()
            return sendResult(response, False, 0)

    def check_url(self):
        '''
        This function works with pam_url.
        '''
        ok = False
        param = self.request_params
        try:
            try:
                (ok, opt) = self._check(param)
            except AuthorizeException as acc:
                log.warning("[check_url] authorization failed for validate/check_url: %r" % acc)
                g.audit['success'] = False
                g.audit['action_detail'] = str(acc)
                ok = False

            db.session.commit()
            response.headers['blablafoo'] = 'application/json'

            ## TODO: this code seems not to be finished
            if not ok:
                abort(403)
            else:
                return "Preshared Key Todo"

        except flap.HTTPUnauthorized as acc:
            ## the exception, when an abort() is called if forwarded
            log.exception("[__before__::%r] webob.exception %r" % acc)
            db.session.rollback()
            raise acc

        except Exception as exx:
            log.exception("[check_url] validate/check_url failed: %r" % exx)
            db.session.rollback()
            return sendResult(response, False, 0)

    def samlcheck(self):
        '''
        This function is used to validate the username and the otp value/password
        in a SAML environment. If ``linotp.allowSamlAttributes = True``
        then the attributes of the authenticated users are also contained
        in the response.

        method:
            validate/samlcheck

        arguments:
            * user:    username / loginname
            * pass:    the password that consists of a possible fixes password component and the OTP value
            * realm:   optional realm to match the user to a useridresolver

        returns:
            JSON response
        '''

        try:
            opt = None
            param = self.request_params
            (ok, opt) = self._check(param)
            attributes = {}

            if True == ok:
                allowSAML = False
                try:
                    allowSAML = getFromConfig("allowSamlAttributes")
                except:
                    log.warning("[samlcheck] Calling controller samlcheck. But allowSamlAttributes is False.")
                if "True" == allowSAML:
                    ## Now we get the attributes of the user
                    user = getUserFromParam(param)
                    (uid, resId, resIdC) = getUserId(user)
                    userInfo = getUserInfo(uid, resId, resIdC)
                    log.debug("[samlcheck] getting attributes for: %s@%s"
                              % (user.login, user.realm))

                    res = userInfo
                    for key in ['username',
                                'surname',
                                'mobile',
                                'phone',
                                'givenname',
                                'email']:
                        if key in res:
                            attributes[key] = res[key]

            db.session.commit()
            return sendResult(response, { 'auth': ok, 'attributes' : attributes } , 0, opt)

        except Exception as exx:
            log.exception("[samlcheck] validate/check failed: %r" % exx)
            db.session.rollback()
            return sendResult(response, False, 0)

    def check_t(self):

        param = self.request_params.copy()
        value = {}
        ok = False
        opt = {}

        try:
            if 'pass' not in param:
                raise ParameterError("Missing parameter: 'pass'")

            passw = param['pass']

            transid = param.get('state', None)
            if transid is not None:
                param['transactionid'] = transid
                del param['state']

            if transid is None:
                transid = param.get('transactionid', None)

            if transid is None:
                raise Exception("missing parameter: state or transactionid!")

            vh = ValidationHandler()
            (ok, opt) = vh.check_by_transactionid(transid=transid,
                                                  passw=passw,
                                                  options=param)

            value['value'] = ok
            value['failcount'] = int(opt.get('failcount', 0))

            g.audit['success'] = ok
            db.session.commit()

            qr = param.get('qr', None)
            if qr and opt and 'message' in opt:
                try:
                    dataobj = opt.get('message')
                    param['alt'] = "%s" % opt
                    if 'transactionid' in opt:
                        param['transactionid'] = opt['transactionid']
                    return sendQRImageResult(response, dataobj, param)
                except Exception as exc:
                    log.warning("failed to send QRImage: %r " % exc)
                    return sendQRImageResult(response, opt, param)
            else:
                return sendResult(response, value, 1, opt=opt)

        except Exception as exx:
            log.exception("[check_t] validate/check_t failed: %r" % exx)
            g.audit['info'] = str(exx)
            db.session.rollback()
            return sendResult(response, False, 0)

    # ------------------------------------------------------------------------ -

    def accept_transaction(self):

        """
        confirms a transaction.

        needs the mandatory url query parameters:

            * transactionid: unique id for the transaction
            * signature: signature for the confirmation
        """

        try:

            param = self.request_params.copy()

            # -------------------------------------------------------------- --

            # check the parameters

            if 'signature' not in param:
                raise ParameterError("Missing parameter: 'signature'!")

            if 'transactionid' not in param:
                raise ParameterError("Missing parameter: 'transactionid'!")

            # -------------------------------------------------------------- --

            # start the processing

            passw = {'accept': param['signature']}
            transid = param['transactionid']

            vh = ValidationHandler()
            ok, _opt = vh.check_by_transactionid(transid=transid,
                                                 passw=passw,
                                                 options=param)

            # -------------------------------------------------------------- --

            # finish the result

            if 'serial' in _opt:
                g.audit['serial'] = _opt['serial']

            if 'token_type' in _opt:
                g.audit['token_type'] = _opt['token_type']

            g.audit['info'] = 'accept transaction: %r' % ok

            g.audit['success'] = ok
            db.session.commit()

            return sendResult(response, ok)

        except Exception as exx:

            log.exception("validate/accept_transaction failed: %r" % exx)
            g.audit['info'] = "%r" % exx
            db.session.rollback()

            return sendResult(response, False, 0)

    # ------------------------------------------------------------------------ -

    def reject_transaction(self):

        """
        rejects a transaction.

        needs the mandatory url query parameters:

            * transactionid: unique id for the transaction
            * signature: signature for the rejection
        """

        try:

            param = self.request_params.copy()

            # -------------------------------------------------------------- --

            # check the parameters

            if 'signature' not in param:
                raise ParameterError("Missing parameter: 'signature'!")

            if 'transactionid' not in param:
                raise ParameterError("Missing parameter: 'transactionid'!")

            # -------------------------------------------------------------- --

            # start the processing

            passw = {'reject': param['signature']}
            transid = param['transactionid']

            vh = ValidationHandler()
            ok, _opt = vh.check_by_transactionid(transid=transid,
                                                 passw=passw,
                                                 options=param)

            # -------------------------------------------------------------- --

            # finish the result

            if 'serial' in _opt:
                g.audit['serial'] = _opt['serial']

            if 'token_type' in _opt:
                g.audit['token_type'] = _opt['token_type']

            g.audit['info'] = 'reject transaction: %r' % ok

            g.audit['success'] = ok
            db.session.commit()

            return sendResult(response, ok)

        except Exception as exx:

            log.exception("validate/reject_transaction failed: %r" % exx)
            g.audit['info'] = "%r" % exx
            db.session.rollback()

            return sendResult(response, False, 0)

    def check_s(self):
        '''
        This function is used to validate the serial and the otp value/password.

        method:
            validate/check_s

        arguments:
            * serial:  the serial number of the token
            * pass:    the password that consists of a possible fixes password component
                        and the OTP value

        returns:
            JSON response
        '''
        param = self.request_params

        options = {}
        options.update(param)
        for k in ['user', 'serial', "pass", "init"]:
            if k in options:
                del options[k]

        try:
            passw = param.get("pass")
            serial = param.get('serial')
            if serial is None:
                user = param.get('user')
                if user is not None:
                    user = getUserFromParam(param)
                    toks = getTokens4UserOrSerial(user=user)
                    if len(toks) == 0:
                        raise Exception("No token found!")
                    elif len(toks) > 1:
                        raise Exception("More than one token found!")
                    else:
                        tok = toks[0].token
                        desc = tok.get()
                        realms = desc.get('LinOtp.RealmNames')
                        if realms is None or len(realms) == 0:
                            realm = getDefaultRealm()
                        elif len(realms) > 0:
                            realm = realms[0]

                        userInfo = getUserInfo(tok.LinOtpUserid,
                                               tok.LinOtpIdResolver,
                                               tok.LinOtpIdResClass)
                        user = User(login=userInfo.get('username'),
                                    realm=realm)

                        serial = tok.getSerial()

            g.audit['serial'] = serial

            options['scope'] = {"check_s": True}
            vh = ValidationHandler()
            (ok, opt) = vh.checkSerialPass(serial, passw, options=options)
            g.audit['success'] = ok
            db.session.commit()

            qr = param.get('qr', None)
            if qr and opt and 'message' in opt:
                try:
                    dataobj = opt.get('message')
                    param['alt'] = "%s" % opt
                    if 'transactionid' in opt:
                        param['transactionid'] = opt['transactionid']
                    return sendQRImageResult(response, dataobj, param)
                except Exception as exc:
                    log.warning("failed to send QRImage: %r " % exc)
                    return sendQRImageResult(response, opt, param)
            else:
                return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("[check_s] validate/check_s failed: %r" % exx)
            g.audit['info'] = str(exx)
            db.session.rollback()
            return sendResult(response, False, id=0, status=False)

    def simplecheck(self):
        '''
        This function is used to validate the username and the otp value/password.

        method:
            validate/simplecheck

        arguments:
            * user:    username / loginname
            * pass:    the password that consists of a possible fixes password component
                        and the OTP value
            * realm:   additional realm to match the user to a useridresolver

        returns:
            Simple ascii response:

            :-)
                in case of success
            :-(
                in case of failed authentication
            :-/
                in case of any error
        '''
        opt = None
        param = self.request_params
        res = []

        try:
            try:
                (ok, opt) = self._check(param)
            except AuthorizeException as e:
                log.warning("[simplecheck] validate/simplecheck: %r" % e)
                g.audit['success'] = False
                g.audit['action_detail'] = str(e)
                ok = False

            db.session.commit()

            if ok is True:
                ret = ":-)"
            else:
                ret = ":-("
            res.append(ret)

            if opt is not None:

                if 'state' in opt or 'transactionid' in opt:
                    stat = opt.get('transactionid') or opt.get('state')
                    res.append(stat)

                if "data" in opt or "message" in opt:
                    msg = opt.get('data') or opt.get('message')
                    res.append(msg)


            return " ".join(res).strip()

        except Exception as exx:
            log.exception("[simplecheck] failed: %r" % exx)
            db.session.rollback()
            return ":-("

    def ok(self):
        return sendResult(response, True, 0)

    def fail(self):
        return sendResult(response, False, 0)

    def smspin(self):
        '''
        This function is used in conjunction with an SMS token:
        the user authenticates with user and pin (pass) and
        will receive on his mobile an OTP as message

        method:
            validate/smspin

        arguments:
            * user:    username / loginname
            * pass:    the password that consists of a possible fixed password
            * realm:   additional realm to match the user to a useridresolver

        returns:
            JSON response
        '''
        ret = False
        param = self.request_params
        state = ''
        message = 'No sms message defined!'

        try:
            user = getUserFromParam(param)
            g.audit['user'] = user.login
            g.audit['realm'] = user.realm or getDefaultRealm()
            g.audit['success'] = 0

            (ret, opt) = self._check(param)

            ## here we build some backward compatibility
            if type(opt) is dict:
                state = opt.get('state', '') or ''
                message = opt.get('message', '') or 'No sms message defined!'

            # sucessfull submit
            if (message in ['sms with otp already submitted',
                            'sms submitted']
                and len(state) > 0):
                ret = True
                g.audit['success'] = 1

            # sending sms failed should be an error
            elif message in ['sending sms failed']:
                ret = True
                g.audit['success'] = 0

            # anything else is an exception
            else:
                raise Exception(message)

            db.session.commit()
            return sendResult(response, ret, opt)

        except Exception as exx:
            log.exception("[smspin] validate/smspin failed: %r" % exx)
            # If an internal error occurs or the SMS gateway did not send
            # the SMS, we write this to the detail info.
            g.audit['info'] = str(exx)
            db.session.rollback()
            return sendResult(response, False, 0)

    def pair(self):
        """
        validate/pair: for the enrollment of qr and push token
        """

        try:

            # -------------------------------------------------------------- --

            enc_response = self.request_params.get('pairing_response')

            if enc_response is None:
                raise Exception('Parameter missing')

            # -------------------------------------------------------------- --

            dec_response = decrypt_pairing_response(enc_response)
            token_type = dec_response.token_type
            pairing_data = dec_response.pairing_data

            if not hasattr(pairing_data, 'serial') or \
               pairing_data.serial is None:

                raise ValidateError('Pairing responses with no serial attached'
                                    ' are currently not implemented.')

            # --------------------------------------------------------------- -

            # TODO: pairing policy
            tokens = getTokens4UserOrSerial(None, pairing_data.serial)

            if not tokens:
                raise Exception('Invalid serial in pairing response')

            if len(tokens) > 1:
                raise Exception('Multiple tokens found. Pairing not possible')

            token = tokens[0]

            # prepare some audit entries
            t_owner = token.getUser()

            realms = token.getRealms()
            realm = ''
            if realms:
                realm = realms[0]

            g.audit['user'] = t_owner or ''
            g.audit['realm'] = realm

            # --------------------------------------------------------------- --

            if token.type != token_type:
                raise Exception('Serial in pairing response doesn\'t match '
                                'supplied token_type')

            # --------------------------------------------------------------- --

            token.pair(pairing_data)
            g.audit['success'] = 1
            g.audit['serial'] = token.getSerial()

            db.session.commit()
            return sendResult(response, False)

        # ------------------------------------------------------------------- --

        except Exception as exx:
            log.exception("validate/pair failed: %r" % exx)
            g.audit['info'] = str(exx)
            db.session.rollback()
            return sendResult(response, False, 0, status=False)

# eof #########################################################################
