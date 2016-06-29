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
""" contains several token api functions"""

import binascii
import string
import datetime
import logging
import string
import sys

import re
import binascii


import os

try:
    import json
except ImportError:
    import simplejson as json

from sqlalchemy import or_, and_, not_
from sqlalchemy import func


from pylons import config
from pylons.configuration import config as env

from linotp.lib.challenges import Challenges

from linotp.lib.error import TokenAdminError
from linotp.lib.error import ParameterError

from linotp.lib.user import getUserId, getUserInfo
from linotp.lib.user import User, getUserRealms
from linotp.lib.user import get_authenticated_user

from linotp.lib.util import getParam
from linotp.lib.util import generate_password

from linotp.lib.realm import realm2Objects
from linotp.lib.realm import getRealms

import linotp
import linotp.lib.policy

from linotp import model
from linotp.model import Token, createToken, Realm, TokenRealm

from linotp.model import Challenge

from linotp.lib.config import getFromConfig

from linotp.lib.realm import createDBRealm, getRealmObject
# getDefaultRealm wird in tokenclass gebraucht:
from linotp.lib.realm import getDefaultRealm

import linotp.model.meta
Session = linotp.model.meta.Session

from linotp.lib.context import request_context as context

from linotp.lib.policy import get_auth_forward
from linotp.lib.policy.forward import ForwardServerPolicy

log = logging.getLogger(__name__)

optional = True
required = False

ENCODING = "utf-8"

###############################################



class TokenHandler(object):

    def initToken(self, param, user, tokenrealm=None):
        '''
        initToken - create a new token or update a token

        :param param: the list of provided parameters
                      in the list the serialnumber is required,
                      the token type default ist hmac
        :param user:  the token owner
        :param tokenrealm: the realms, to which the token belongs

        :return: tuple of success and token object
        '''
        log.debug("[initToken] begin. create token with param %r for user"
                  " %r and tokenrealm %r" % (param, user, tokenrealm))

        token = None

        # if we get a undefined tokenrealm , we create a list
        if tokenrealm is None:
            tokenrealm = []
        # if we get a tokenrealm as string, we make an array out of this
        elif type(tokenrealm) in [str, unicode]:
            tokenrealm = [tokenrealm]
        # if there is a realm as parameter, we assign the token to this realm
        if 'realm' in param:
            # # and append our parameter realm
            tokenrealm.append(param.get('realm'))

        typ = getParam(param, "type", optional)
        if typ is None:
            typ = "hmac"

        # serial = getParam(param, "serial", required)
        serial = param.get('serial', None)
        if serial is None:
            prefix = param.get('prefix', None)
            serial = self.genSerial(typ, prefix)

        # if a token was initialized for a user, the param "realm" might
        # be contained. otherwise - without a user the param tokenrealm could
        # be contained.
        log.debug("[initToken] initilizing token %r for user %r "
                  % (serial, user.login))

        #  create a list of the found db tokens - no token class objects
        toks = getTokens4UserOrSerial(None, serial, _class=False)
        tokenNum = len(toks)

        tokenclasses = config['tokenclasses']

        if tokenNum == 0:  # create new a one token
            #  check if this token is in the list of available tokens
            if typ.lower() not in tokenclasses:
                log.error('[initToken] typ %r not found in tokenclasses: %r' %
                          (typ, tokenclasses))
                raise TokenAdminError("[initToken] failed: unknown token "
                                      "type %r" % typ, id=1610)
            token = createToken(serial)

        elif tokenNum == 1:  # update if already there
            token = toks[0]

            # prevent from changing the token type
            old_typ = token.LinOtpTokenType
            if old_typ.lower() != typ.lower():
                msg = ('token %r already exist with type %r. Can not '
                       'initialize token with new type %r'
                       % (serial, old_typ, typ))
                log.error('[initToken] %s' % msg)
                raise TokenAdminError("initToken failed: %s" % msg)

            #  prevent update of an unsupported token type
            if typ.lower() not in tokenclasses:
                log.error('[initToken] typ %r not found in tokenclasses: %r' %
                          (typ, tokenclasses))
                raise TokenAdminError("[initToken] failed: unknown token"
                                      " type %r" % typ, id=1610)

        else:  # something wrong
            if tokenNum > 1:
                raise TokenAdminError("multiple tokens found - cannot init!",
                                      id=1101)
            else:
                raise TokenAdminError("cannot init! Unknown error!", id=1102)

        # get the RealmObjects of the user and the tokenrealms
        realms = getRealms4Token(user, tokenrealm)
        token.setRealms(realms)


        #  on behalf of the type, the class is created
        tokenObj = createTokenClassObject(token, typ)

        if tokenNum == 0:
            # if this token is a newly created one, we have to setup the
            # defaults, which lateron might be overwritten by the
            # tokenObj.update(params)
            tokenObj.setDefaults()

        tokenObj.update(param)

        if user is not None and user.login != "":
            tokenObj.setUser(user, report=True)

        try:
            token.storeToken()
        except Exception as exx:
            log.error('[initToken] token create failed!')
            log.exception("[initToken] %r", exx)
            raise TokenAdminError("token create failed %r" % exx, id=1112)

        log.debug("[initToken] end. created tokenObject %r and returning"
                  " status %r " % (True, tokenObj))
        return (True, tokenObj)

    def auto_enrollToken(self, passw, user, options=None):
        '''
        This function is called to auto_enroll a token:
        - when the user has no token assigned and enters his password (without
          otppin=1 policy), a new email or sms token is created and will be
          assigned to the user. Finaly a challenge otp for this user will be
          created that he will receive by email or sms.

        :param passw: password of the user - to checked against
                      the user resolver
        :param user: user object of login name and realm
        :param options: optional parameters used during challenge creation
        :return: tuple of auth success and challenge output
        '''

        # check if autoenrollt is configured
        auto = False
        try:
            auto, token_type = linotp.lib.policy.get_auto_enrollment(user)
        except Exception as exx:
            log.exception("%r", exx)
            raise Exception("[auto_enrollToken] %r" % exx)

        if not auto:
            msg = ("no auto_enrollToken configured")
            log.debug(msg)
            return False, None

        uid, res, resc = getUserId(user)
        u_info = getUserInfo(uid, res, resc)

        # enroll token for user
        desc = 'auto enrolled for %s@%s' % (user.login, user.realm)
        token_init = {'genkey': 1, "type": token_type,
                      'description': desc[:80]}

        # for sms get phone number of user
        if token_type == 'sms':
            mobile = u_info.get('mobile', None)
            if not mobile:
                msg = ('auto_enrollemnt for user %s faild: missing '
                       'mobile number!' % user)
                log.warning(msg)
                return False, {'error': msg}

            token_init['phone'] = mobile

        # for email get email address
        elif token_type == 'email':
            email = u_info.get('email', None)
            if not email:
                msg = ('auto_enrollemnt for user %s faild: missing email!'
                            % user)
                log.warning(msg)
                return False, {'error': msg}
            token_init['email_address'] = email

        # else: token type undefined
        else:
            msg = ('auto_enrollemnt for user %s faild: unknown token type %r'
                        % (user, token_type))
            log.warning(msg)
            return False, {'error': msg}

        authUser = get_authenticated_user(user.login, user.realm, passw)
        if authUser is None:
            msg = ("User %r@%r failed to authenticate against userstore"
                      % (user.login, user.realm))
            log.error(msg)
            return False, {'error': msg}

        # if the passw is correct we use this as an initial pin
        # to prevent otp spoof from email or sms
        token_init['pin'] = passw

        (res, tokenObj) = self.initToken(token_init, user)
        if res is False:
            msg = ('Failed to create token for user %s@%s during'
                   ' autoenrollment' % (user.login, user.realm))
            log.error(msg)
            return False, {'error': msg}

        # we have to use a try except as challenge creation might raise
        # exception and we have to drop the created token
        try:
            # trigger challenge for user
            (_res, reply) = Challenges.create_challenge(tokenObj,
                                                        options=options)
            if _res is not True:
                error = ('failed to create challenge for user %s@%s during '
                         'autoenrollment' % (user.login, user.realm))
                log.error(error)
                raise Exception(error)

        except Exception as exx:
            log.exception("%r", exx)
            # we have to commit our token delete as the rollback
            # on exception does not :-(
            Session.delete(tokenObj.token)
            Session.commit()
            raise exx

        return (True, reply)

    def losttoken(self, serial, new_serial=None, password=None,
                  default_validity=0, param=None):
        """
        This is the workflow to handle a lost token

        :param serial: Token serial number
        :param new_serial: new serial number
        :param password: new password
        :param default_validity: set the token to be valid
        :param param: additional arguments for the password, email or sms token
            as dict

        :return: result dictionary
        """

        res = {}

        if param is None:
            param = {'type': 'password'}

        owner = self.getTokenOwner(serial)
        log.info("lost token for serial %r and owner %r@%r"
                                        % (serial, owner.login, owner.realm))

        if owner.login == "" or owner.login is None:
            err = "You can only define a lost token for an assigned token."
            log.warning("%s" % err)
            raise Exception(err)

        client = context['Client']

        pol = linotp.lib.policy.get_client_policy(client,
                                        scope="enrollment", realm=owner.realm,
                                        user=owner.login, userObj=owner)

        validity = linotp.lib.policy.getPolicyActionValue(pol,
                                                          "lostTokenValid",
                                                          max=False)

        if validity == -1:
            validity = 10
        if 0 != default_validity:
            validity = default_validity

        log.debug("losttoken: validity: %r" % (validity))

        if not new_serial:
            new_serial = "lost%s" % serial

        res['serial'] = new_serial
        init_params = {'type': 'pw',
                       "serial": new_serial,
                       "description": "temporary replacement for %s" % serial
                        }

        if 'type' in param:
            if param['type'] == 'password':
                init_params['type'] = 'pw'

            elif param['type'] == 'email':
                email = param.get('email', owner.info.get('email', None))
                if email:
                    init_params['type'] = 'email'
                    init_params["genkey"] = 1
                    init_params['email_address'] = email
                else:
                    log.warning('no email address found for %s' % owner.login)
                    log.warning('falling back to password token!')

            elif param['type'] == 'sms':
                phone = param.get('mobile', owner.info.get('mobile', None))
                if phone:
                    init_params['type'] = 'sms'
                    init_params["genkey"] = 1
                    init_params['phone'] = phone
                else:
                    log.warning('no mobile number found for %s' % owner.login)
                    log.warning('falling back to password token!')

        if init_params['type'] == 'pw':
            pw_len = linotp.lib.policy.getPolicyActionValue(pol,
                                                            "lostTokenPWLen")

            if pw_len == -1:
                pw_len = 10

            contents = linotp.lib.policy.getPolicyActionValue(pol,
                                            "lostTokenPWContents",
                                            is_string=True)

            character_pool = "%s%s%s" % (string.ascii_lowercase,
                                         string.ascii_uppercase, string.digits)
            if contents != "":
                character_pool = ""
                if "c" in contents:
                    character_pool += string.ascii_lowercase
                if "C" in contents:
                    character_pool += string.ascii_uppercase
                if "n" in contents:
                    character_pool += string.digits
                if "s" in contents:
                    character_pool += "!#$%&()*+,-./:;<=>?@[]^_"

            if not password:
                password = generate_password(size=pw_len,
                                             characters=character_pool)

            init_params["otpkey"] = password

        # now we got all info and can enroll the replacement token
        (ret, tokenObj) = self.initToken(param=init_params,
                                         user=User('', '', ''))

        res['init'] = ret
        if True == ret:
            # copy the assigned user
            res['user'] = self.copyTokenUser(serial, new_serial)

            # copy the pin, except for spass
            # (because the pin is the spass password, and the user lost it)
            if getTokenType(serial) not in ["spass"]:
                res['pin'] = self.copyTokenPin(serial, new_serial)

            # set validity period
            end_date = (datetime.date.today()
                        + datetime.timedelta(days=validity)).\
                        strftime("%d/%m/%y")

            end_date = "%s 23:59" % end_date
            tokenObj.set_validity_period_end(end_date)

            # fill results
            res['valid_to'] = "xxxx"
            if init_params['type'] == 'pw':
                res['password'] = password
            elif init_params['type'] == 'email':
                res['password'] = "Please check your emails"
            elif init_params['type'] == 'sms':
                res['password'] = "Please check your phone"
            res['end_date'] = end_date

            # we need to return the token type, so we can modify the
            # response according
            res['token_typ'] = init_params['type']

            # disable token
            res['disable'] = self.enableToken(False, User('', '', ''), serial)

        return res


    def isTokenOwner(self, serial, user):
        ret = False

        userid = ""
        idResolver = ""
        idResolverClass = ""

        log.debug("[isTokenOwner] entering function isTokenOwner")

        if user is not None and (user.isEmpty() is False):
        # the upper layer will catch / at least should
            (userid, idResolver, idResolverClass) = getUserId(user)

        if len(userid) + len(idResolver) + len(idResolverClass) == 0:
            log.info("[isTokenOwner] no user found %r", user.login)
            raise TokenAdminError("no user found %s" % user.login, id=1104)

        toks = getTokens4UserOrSerial(None, serial)

        if len(toks) > 1:
            log.info("[isTokenOwner] multiple tokens found for user %r"
                     % user.login)
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            log.info("[isTokenOwner] no tokens found for user %r", user.login)
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]

        (uuserid, uidResolver, uidResolverClass) = token.getUser()

        if uidResolver == idResolver:
            if uidResolverClass == idResolverClass:
                if uuserid == userid:
                    ret = True

        return ret

    def hasOwner(self, serial):
        '''
        returns true if the token is owned by any user
        '''
        ret = False

        log.debug('[hasOwner] entering function hasOwner()')

        toks = getTokens4UserOrSerial(None, serial)

        if len(toks) > 1:
            log.info("[hasOwner] multiple tokens found with serial %r"
                     % serial)
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            log.info("[hasOwner] no token found with serial %r" % serial)
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]

        (uuserid, uidResolver, uidResolverClass) = token.getUser()

        if len(uuserid) + len(uidResolver) + len(uidResolverClass) > 0:
            ret = True

        return ret

    def getTokenOwner(self, serial):
        '''
        returns the user object, to which the token is assigned.
        the token is idetified and retirved by it's serial number

        :param serial: serial number of the token
        :return: user object
        '''
        log.debug("[getTokenOwner] getting token owner for serial: %r"
                  % serial)
        token = None

        toks = getTokens4UserOrSerial(None, serial)
        if len(toks) > 0:
            token = toks[0]

        user = get_token_owner(token)

        return user


    def check_serial(self, serial):
        '''
        This checks, if a serial number is already contained.

        The function returns a tuple:
            (result, new_serial)

        If the serial is already contained a new, modified serial new_serial
        is returned.

        result: bool: True if the serial does not already exist.
        '''
        # serial does not exist, yet
        result = True
        new_serial = serial
        log.debug("[check_serial] check if token %r already exists" % serial)

        i = 0
        while len(getTokens4UserOrSerial(None, new_serial)) > 0:
            # as long as we find a token, modify the serial:
            i = i + 1
            result = False
            new_serial = "%s_%02i" % (serial, i)

        return (result, new_serial)

    def auto_assignToken(self, passw, user, _pin="", param=None):
        '''
        This function is called to auto_assign a token, when the
        user enters an OTP value of an not assigned token.
        '''
        ret = False
        auto = False

        if param is None:
            param = {}

        try:
            auto = linotp.lib.policy.get_autoassignment(user)
        except Exception as exx:
            log.exception("[auto_assignToken] %r", exx)

        # check if autoassignment is configured
        if not auto:
            log.debug("[auto_assignToken] not autoassigment configured")
            return False

        # check if user has a token
        # TODO: this may dependend on a policy definition
        tokens = getTokens4UserOrSerial(user, "")
        if len(tokens) > 0:
            log.debug("[auto_assignToken] no auto_assigment for user %r@%r. "
                      "He already has some tokens." % (user.login, user.realm))
            return False

        # List of (token, pin) pairs
        matching_pairs = []

        # get all tokens of the users realm, which are not assigned

        tokens = self.getTokensOfType(typ=None, realm=user.realm, assigned="0")
        for token in tokens:

            token_exists = -1
            from linotp.lib import policy
            if (policy.autoassignment_forward(user)
                        and token.type == 'remote'):
                ruser = User(user.login, user.realm)
                token_exists = token.check_otp_exist(otp=passw,
                                          window=token.getOtpCountWindow(),
                                          user=ruser, autoassign=True)
                (pin, otp) = token.splitPinPass(passw)
            else:
                (pin, otp) = token.splitPinPass(passw)
                token_exists = token.check_otp_exist(otp=otp,
                                          window=token.getOtpCountWindow())

            if token_exists >= 0:
                matching_pairs.append((token, pin))

        if len(matching_pairs) != 1:
            log.warning("[auto_assignToken] %d tokens with "
                        "the given OTP value found.", len(matching_pairs))
            return False

        token, pin = matching_pairs[0]
        serial = token.getSerial()

        authUser = get_authenticated_user(user.login, user.realm, pin)
        if authUser is None:
            log.error("[auto_assignToken] User %r@%r failed to authenticate "
                      "against userstore" % (user.login, user.realm))
            return False

        log.debug("[auto_assignToken] found serial number: %r" % serial)

        # should the password of the autoassignement be used as pin??
        if True == linotp.lib.policy.ignore_autoassignment_pin(user):
            pin = None

        # if found, assign the found token to the user.login
        try:
            self.assignToken(serial, user, pin)
            context['audit']['serial'] = serial
            context['audit']['info'] = "Token auto assigned"
            context['audit']['token_type'] = token.getType()
            ret = True
        except Exception as exx:
            log.exception("[auto_assignToken] Failed to assign token: %r", exx)
            return False

        return ret

    def assignToken(self, serial, user, pin, param=None):
        '''
        assignToken - used to assign and to unassign token
        '''
        if param is None:
            param = {}

        log.debug('[assignToken] entering function assignToken()')
        toks = getTokens4UserOrSerial(None, serial)
        # toks  = Session.query(Token).filter(
        #  Token.LinOtpTokenSerialnumber == serial)

        if len(toks) > 1:
            log.warning("[assignToken] multiple tokens found with serial: %r"
                        % serial)
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            log.warning("[assignToken] no tokens found with serial: %r"
                        % serial)
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]
        if (user.login == ""):
            report = False
        else:
            report = True

        token.setUser(user, report)

        #  set the Realms of the Token
        realms = getRealms4Token(user)
        token.setRealms(realms)

        if pin is not None:
            token.setPin(pin, param)

        #  reset the OtpCounter
        token.setFailCount(0)

        try:
            token.storeToken()
        except Exception as exx:
            log.exception('[assign Token] update Token DB failed: %r', exx)
            raise TokenAdminError("Token assign failed for %s/%s : %r"
                                  % (user.login, serial, exx), id=1105)

        log.debug("[assignToken] successfully assigned token with serial "
                  "%r to user %r" % (serial, user.login))
        return True

    def unassignToken(self, serial, user=None, pin=None):
        '''
        unassignToken - used to assign and to unassign token
        '''
        log.debug('[unassignToken] entering function unassignToken()')
        toks = getTokens4UserOrSerial(None, serial)
        # toks  = Session.query(Token).filter(
        #               Token.LinOtpTokenSerialnumber == serial)

        if len(toks) > 1:
            log.warning("[unassignToken] multiple tokens found with serial: %r"
                        % serial)
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            log.warning("[unassignToken] no tokens found with serial: %r"
                        % serial)
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]
        no_user = User('', '', '')
        token.setUser(no_user, True)
        if pin:
            token.setPin(pin)

        #  reset the OtpCounter
        token.setFailCount(0)

        try:
            token.storeToken()
        except Exception as exx:
            log.exception('[unassignToken] update token DB failed %r', exx)
            raise TokenAdminError("Token unassign failed for %r/%r: %r"
                                  % (user, serial, exx), id=1105)

        log.debug("[unassignToken] successfully unassigned token with serial"
                  " %r" % serial)
        return True

    def get_serial_by_otp(self, token_list=None, otp="", window=10, typ=None,
                          realm=None, assigned=None):
        '''
        Returns the serial for a given OTP value and the user
        (serial, user)

        :param otp:      -  the otp value to be searched
        :param window:   -  how many OTPs should be calculated per token
        :param typ:      -  The tokentype
        :param realm:    -  The realm in which to search for the token
        :param assigned: -  search either in assigned (1) or
                            not assigend (0) tokens

        :return: the serial for a given OTP value and the user
        '''
        serial = ""
        username = ""
        resolverClass = ""

        token = self.get_token_by_otp(token_list, otp, window, typ, realm,
                                      assigned)

        if token is not None:
            serial = token.getSerial()
            uid, resolver, resolverClass = token.getUser()
            userInfo = getUserInfo(uid, resolver, resolverClass)
            log.debug("[get_serial_by_otp] userinfo for token: %r" % userInfo)
            username = userInfo.get("username", "")

        return serial, username, resolverClass

# local
    def get_token_by_otp(self, token_list=None, otp="", window=10, typ=u"HMAC",
                         realm=None, assigned=None):
        '''
        method
            get_token_by_otp    - from the given token list this function returns
                                  the token, that generates the given OTP value
        :param token_list:        - the list of token objects to be investigated
        :param otpval:            - the otp value, that needs to be found
        :param window:            - the window of search
        :param assigned:          - or unassigned tokens (1/0)

        :return:         returns the token object.
        '''
        result_token = None

        validation_results = []
        log.debug("[get_token_by_otp] entering function. Searching for otp=%r" % otp)

        if token_list is None:
            token_list = self.getTokensOfType(typ, realm, assigned)

        for token in token_list:
            log.debug("[get_token_by_otp] checking token %r" % token.getSerial())
            r = token.check_otp_exist(otp=otp, window=window)
            log.debug("[get_token_by_otp] result = %d" % int(r))
            if r >= 0:
                validation_results.append(token)

        if len(validation_results) == 1:
            result_token = validation_results[0]
        elif len(validation_results) > 1:
            raise TokenAdminError("get_token_by_otp: multiple tokens are "
                                  "matching this OTP value!", id=1200)

        return result_token

    # local method
    def getTokensOfType(self, typ=None, realm=None, assigned=None):
        '''
        This function returns a list of token objects of the following type.

        here we need to create the token list.
           1. all types (if typ==None)
           2. realms
           3. assigned or unassigned tokens (1/0)
        TODO: rename function to "getTokens"
        '''
        tokenList = []
        log.debug("[getTokensOfType] searching tokens type=%r, realm=%r,"
                  " assigned=%r" % (typ, realm, assigned))
        sqlQuery = Session.query(Token)
        if typ is not None:
            # filter for type
            sqlQuery = sqlQuery.\
                filter(func.lower(Token.LinOtpTokenType) == typ.lower())
        if assigned is not None:
            # filter if assigned or not
            if "0" == unicode(assigned):
                sqlQuery = sqlQuery.filter(or_(Token.LinOtpUserid == None,
                                               Token.LinOtpUserid == ""))
            elif "1" == unicode(assigned):
                sqlQuery = sqlQuery.filter(func.length(Token.LinOtpUserid) > 0)
            else:
                log.warning("[getTokensOfType] assigned value not in [0,1] %r"
                            % assigned)

        if realm is not None:
            # filter for the realm
            sqlQuery = sqlQuery\
                .filter(and_(func.lower(Realm.name) == realm.lower(),
                        TokenRealm.realm_id == Realm.id,
                        TokenRealm.token_id == Token.LinOtpTokenId)).distinct()

        for token in sqlQuery:
            log.debug("[getTokensOfType] adding token with serial %r"
                      % token.LinOtpTokenSerialnumber)
            # the token is the database object, but we want
            # an instance of the tokenclass!
            tokenList.append(createTokenClassObject(token))

        return tokenList

    def removeToken(self, user=None, serial=None):
        """
        delete a token from database

        :param user: the tokens of the user
        :param serial: the token with this serial number

        :return: the number of deleted tokens
        """
        if (user is None or user.isEmpty() is True) and (serial is None):
            log.warning("[removeToken] Parameter user or serial required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[removeToken] for serial: %r, user: %r" % (serial, user))
        tokenList = getTokens4UserOrSerial(user, serial, _class=False)

        serials = []
        tokens = []
        token_ids = []
        try:

            for token in tokenList:
                ser = token.getSerial()
                serials.append(ser)
                token_ids.append(token.LinOtpTokenId)
                tokens.append(token)

            #  we cleanup the challenges
            challenges = set()
            for serial in serials:
                serial = linotp.lib.crypt.uencode(serial)
                challenges.update(Challenges.lookup_challenges(serial=serial))

            for chall in challenges:
                Session.delete(chall)

            #  due to legacy SQLAlchemy it could happen that the
            #  foreign key relation could not be deleted
            #  so we do this manualy

            for t_id in token_ids:
                Session.query(TokenRealm).filter(
                                    TokenRealm.token_id == t_id).delete()

            Session.commit()

            for token in tokens:
                Session.delete(token)

        except Exception as exx:
            log.exception('[removeToken] update token DB failed %r', exx)
            raise TokenAdminError("removeToken: Token update failed: %r"
                                   % exx, id=1132)

        return len(tokenList)

    def setCounterWindow(self, countWindow, user, serial):

        if user is None and serial is None:
            log.warning("[setCounterWindow] Parameter serial or user required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setCounterWindow] setting count window for serial %r" % serial)
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.setCounterWindow(countWindow)

        return len(tokenList)

    def setDescription(self, description, user, serial):

        if user is None and serial is None:
            log.warning("[setDescription] Parameter serial or user required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setDescription] setting count window for serial %r" % serial)
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.setDescription(description)

        return len(tokenList)

    def setHashLib(self, hashlib, user, serial):
        '''
        sets the Hashlib in the tokeninfo
        '''
        if user is None and serial is None:
            log.warning("[setHashLib] Parameter user or serial required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        if serial is not None:
            log.debug("[setHashLib] setting hashlib for serial %r" % serial)
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.setHashLib(hashlib)

        return len(tokenList)

    def setMaxFailCount(self, maxFail, user, serial):

        if (user is None) and (serial is None):
            log.warning("[setMaxFailCount] Parameter user or serial required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setMaxFailCount] for serial: %r, user: %r"
                  % (serial, user))
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.setMaxFail(maxFail)

        return len(tokenList)

    def setSyncWindow(self, syncWindow, user, serial):

        if user is None and serial is None:
            log.warning("[setSyncWindow] Parameter serial or user required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setSyncWindow] setting syncwindow for serial %r" % serial)
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.setSyncWindow(syncWindow)

        return len(tokenList)

    def setOtpLen(self, otplen, user, serial):

        if (user is None) and (serial is None):
            log.warning("[setOtpLen] Parameter user or serial required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        if (serial is not None):
            log.debug("[setOtpLen] setting OTP length for serial %r" % serial)
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.setOtpLen(otplen)

        return len(tokenList)

    def enableToken(self, enable, user, serial):
        """
        switch the token status to active or inactive
        :param enable: True::active or False::inactive
        :param user: all tokens of this owner
        :param serial: the serial number of the token

        :return: number of changed tokens
        """
        if (user is None) and (serial is None):
            log.warning("[enableToken] parameter serial or user missing.")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[enableToken] enable=%r, user=%r, serial=%r"
                  % (enable, user, serial))
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.enable(enable)

        return len(tokenList)

    def copyTokenPin(self, serial_from, serial_to):
        '''
        This function copies the token PIN from one token to the other token.
        This can be used for workflows like lost token.

        In fact the PinHash and the PinSeed need to be transferred

        returns:
            1 : success
            -1: no source token
            -2: no destination token
        '''
        log.debug("[copyTokenPin] copying PIN from token %r to token %r"
                  % (serial_from, serial_to))
        tokens_from = getTokens4UserOrSerial(None, serial_from)
        tokens_to = getTokens4UserOrSerial(None, serial_to)
        if len(tokens_from) != 1:
            log.error("[copyTokenPin] not a unique token to copy from found")
            return -1
        if len(tokens_to) != 1:
            log.error("[copyTokenPin] not a unique token to copy to found")
            return -2
        import linotp.lib.tokenclass
        linotp.lib.tokenclass.TokenClass.copy_pin(tokens_from[0], tokens_to[0])
        return 1

    def copyTokenUser(self, serial_from, serial_to):
        '''
        This function copies the user from one token to the other
        This can be used for workflows like lost token

        returns:
            1: success
            -1: no source token
            -2: no destination token
        '''
        log.debug("[copyTokenUser] copying user from token %r to token %r"
                  % (serial_from, serial_to))
        tokens_from = getTokens4UserOrSerial(None, serial_from)
        tokens_to = getTokens4UserOrSerial(None, serial_to)
        if len(tokens_from) != 1:
            log.error("[copyTokenUser] not a unique token to copy from found")
            return -1
        if len(tokens_to) != 1:
            log.error("[copyTokenUser] not a unique token to copy to found")
            return -2
        uid, ures, resclass = tokens_from[0].getUser()
        tokens_to[0].setUid(uid, ures, resclass)

        self.copyTokenRealms(serial_from, serial_to)
        return 1

    # local
    def copyTokenRealms(self, serial_from, serial_to):
        realmlist = getTokenRealms(serial_from)
        setRealms(serial_to, realmlist)

    def addTokenInfo(self, info, value, user, serial):
        '''
        sets an abitrary Tokeninfo field
        '''
        if user is None and serial is None:
            log.warning("[setTokenInfo] Parameter user or serial required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        if serial is not None:
            log.debug("[setTokenInfo] setting tokeninfo %r for serial %r"
                      % (info, serial))
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            token.addToTokenInfo(info, value)

        return len(tokenList)

    def resyncToken(self, otp1, otp2, user, serial, options=None):
        """
        resync a token by its consecutive otps

        :param user: the token owner
        :param serial: the serial number of the token
        :param options: the additional command parameters for specific token
        :return: Success by a boolean
        """
        ret = False

        if (user is None) and (serial is None):
            log.warning("[resyncToken] Parameter serial or user required!")
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[resyncToken] resync token with serial %r" % serial)
        tokenList = getTokens4UserOrSerial(user, serial)

        for token in tokenList:
            token.addToSession(Session)
            res = token.resync(otp1, otp2, options)
            if res is True:
                ret = True
        return ret

    def genSerial(self, tokenType=None, prefix=None):
        '''
        generate a serial number similar to the one generated in the
        manage web gui

        :param tokenType: the token type prefix is done by
                          a lookup on the tokens
        :return: serial number
        '''
        if tokenType is None:
            tokenType = 'LSUN'

        tokenprefixes = config['tokenprefixes']

        if prefix is None:
            prefix = tokenType.upper()
            if tokenType.lower() in tokenprefixes:
                prefix = tokenprefixes.get(tokenType.lower())

        #  now search the number of ttypes in the token database
        tokennum = Session.query(Token).filter(
                        Token.LinOtpTokenType == u'' + tokenType).count()

        serial = _gen_serial(prefix, tokennum + 1)

        #  now test if serial already exists
        while True:
            numtokens = Session.query(Token).filter(
                        Token.LinOtpTokenSerialnumber == u'' + serial).count()
            if numtokens == 0:
                #  ok, there is no such token, so we're done
                break
            #  else - rare case:
            #  we add the numtokens to the number of existing tokens
            # with serial
            serial = _gen_serial(prefix, tokennum + numtokens)

        return serial

    def __llast(self):
        pass


# local

def createTokenClassObject(token, typ=None):
    '''
    createTokenClassObject - create a token class object from a given type

    :param token:  the database refeneced token
    :type  token:  database token
    :param typ:    type of to be created token
    :type  typ:    string

    :return: instance of the token class object
    :rtype:  token class object
    '''

    # if type is not given, we take it out of the token database object
    if (typ is None):
        typ = token.LinOtpTokenType

    if typ == "":
        typ = "hmac"

    typ = typ.lower()
    tok = None

    # search which tokenclass should be created and create it!
    tokenclasses = config['tokenclasses']
    if tokenclasses.has_key(typ.lower()):
        try:
            token_class = tokenclasses.get(typ)
            tok = newToken(token_class)(token)

        except Exception as exx:
            log.exception('createTokenClassObject failed! %r', exx)
            raise TokenAdminError("createTokenClassObject failed:  %r"
                                  % exx, id=1609)

    else:
        log.error('[createTokenClassObject] typ %r not found in tokenclasses: %r' %
                  (typ, tokenclasses))
        #
        #  we try to use the parent class, which is able to handle most of the
        #  administrative tasks. This will allow to unassigen and disable or delete
        #  this 'abandoned token'
        #
        from linotp.lib.tokenclass import TokenClass
        tok = TokenClass(token)
        log.error("[createTokenClassObject] failed: unknown token type %r. \
                 Using fallback 'TokenClass' for %r" % (typ, token))

    return tok

def newToken(token_class):
    '''
    newTokenClass - return a token class, which could be used as a constructor

    :param token_class: string representation of the token class name
    :type   token_class: string
    :return: token class
    :rtype:  token class

    '''

    ret = ""
    attribute = ""

    #  prepare the lookup
    parts = token_class.split('.')
    package_name = '.'.join(parts[:-1])
    class_name = parts[-1]

    if sys.modules.has_key(package_name):
        mod = sys.modules.get(package_name)
    else:
        mod = __import__(package_name, globals(), locals(), [class_name])
    try:
        klass = getattr(mod, class_name)

        attrs = ["getType", "checkOtp"]
        for att in attrs:
            attribute = att
            getattr(klass, att)

        ret = klass
    except:
        raise NameError(
            "IdResolver AttributeError: " + package_name + "." + class_name
             + " instance has no attribute '" + attribute + "'")
    return ret


def get_token_type_list():
    '''
    get_token_type_list - returns the list of the available tokentypes like hmac, spass, totp...

    :return: list of token types
    :rtype : list
    '''

    try:
#        from linotp.lib.config      import getGlobalObject
        tokenclasses = config['tokenclasses']

    except Exception as exx:
        log.exception('get_token_type_list failed! %r', exx)
        raise TokenAdminError('get_token_type_list failed:  %r' % exx, id=1611)

    token_type_list = tokenclasses.keys()
    return token_type_list



def getRealms4Token(user, tokenrealm=None):
    """
    get the realm objects of a user or from the tokenrealm defintion,
    which could be a list of realms or a single realm

    helper method to enhance the code readability

    :param user: the user wich defines the set of realms
    :param tokenrealm: a string or a list of realm strings

    :return: the list of realm objects
    """

    realms = []
    if user is not None and user.login != "" :
        #  the getUserRealms should return the default realm if realm was empty
        realms = getUserRealms(user)
        #  hack: sometimes the realm of the user is not in the
        #  realmDB - so check and add
        for r in realms:
            realmObj = getRealmObject(name=r)
            if realmObj is None:
                createDBRealm(r)

    if tokenrealm is not None:
        # tokenrealm can either be a string or a list
        log.debug("[getRealms4Token] tokenrealm given (%r). We will add the "
                  "new token to this realm" % tokenrealm)
        if type(tokenrealm) in [str, unicode]:
            log.debug("[getRealms4Token] String: adding realm: %r" % tokenrealm)
            realms.append(tokenrealm)
        elif type(tokenrealm) in [list]:
            for tr in tokenrealm:
                log.debug("[getRealms4Token] List: adding realm: %r" % tr)
                realms.append(tr)

    realmList = realm2Objects(realms)

    return realmList


def get_tokenserial_of_transaction(transId):
    '''
    get the serial number of a token from a challenge state / transaction

    :param transId: the state / transaction id
    :return: the serial number or None
    '''
    serials = []

    challenges = Challenges.lookup_challenges(transid=transId)

    for challenge in challenges:
        serials.append(challenge.tokenserial)

    return serials


def getRolloutToken4User(user=None, serial=None, tok_type=u'ocra'):

    if (user is None or user.isEmpty()) and serial is None:
        return None

    serials = []
    tokens = []

    if user is not None and user.isEmpty() is False and user.login:
        resolverUid = user.resolverUid
        v = None
        k = None
        for k in resolverUid:
            v = resolverUid.get(k)
        user_id = v

        # in the database could be tokens of ResolverClass:
        #    useridresolver. or useridresolveree.
        # so we have to make sure
        # - there is no 'useridresolveree' in the searchterm and
        # - there is a wildcard search: second replace
        # Remark: when the token is loaded the response to the
        # resolver class is adjusted

        user_resolver = k.replace('useridresolveree.', 'useridresolver.')
        user_resolver = user_resolver.replace('useridresolver.', 'useridresolver%.')

        ''' coout tokens: 0 1 or more '''
        tokens = Session.query(Token).filter(Token.LinOtpTokenType == unicode(tok_type))\
                                       .filter(Token.LinOtpIdResClass.like(unicode(user_resolver)))\
                                       .filter(Token.LinOtpUserid == unicode(user_id))

    elif serial is not None:
        tokens = Session.query(Token).filter(Token.LinOtpTokenType == unicode(tok_type))\
                                       .filter(Token.LinOtpTokenSerialnumber == unicode(serial))

    for token in tokens:
        info = token.LinOtpTokenInfo
        if len(info) > 0:
            tinfo = json.loads(info)
            rollout = tinfo.get('rollout', None)
            if rollout is not None:
                serials.append(token.LinOtpTokenSerialnumber)


    if len(serials) > 1:
        raise Exception('multiple tokens found in rollout state: %s'
                        % unicode(serials))

    if len(serials) == 1:
        serial = serials[0]

    return serial

def setRealms(serial, realmList):
    # set the tokenlist of DB tokens
    tokenList = getTokens4UserOrSerial(None, serial, _class=False)

    if len(tokenList) == 0:
        log.error("[setRealms] No token with serial %r found." % serial)
        raise TokenAdminError("setRealms failed. No token with serial %s found"
                              % serial, id=1119)

    realmObjList = realm2Objects(realmList)

    for token in tokenList:
        token.setRealms(realmObjList)

    return len(tokenList)

def getTokenRealms(serial):
    '''
    This function returns a list of the realms of a token
    '''
    tokenList = getTokens4UserOrSerial(None, serial, _class=False)

    if len(tokenList) == 0:
        log.error("[getTokenRealms] No token with serial %r found." % serial)
        raise TokenAdminError("getTokenRealms failed. No token with serial %s found" % serial, id=1119)

    token = tokenList[0]

    return token.getRealmNames()

def getRealmsOfTokenOrUser(token):
    '''
    This returns the realms of either the token or
    of the user of the token.
    '''
    serial = token.getSerial()
    realms = getTokenRealms(serial)

    if len(realms) == 0:
        uid, resolver, resolverClass = token.getUser()
        log.debug("[getRealmsOfTokenOrUser] %r, %r, %r" % (uid, resolver, resolverClass))
        # No realm and no User, this is the case in /validate/check_s
        if resolver.find('.') >= 0:
            resotype, resoname = resolver.rsplit('.', 1)
            realms = getUserRealms(User("dummy_user", "", resoname))

    log.debug("[getRealmsOfTokenOrUser] the token %r "
              "is in the following realms: %r" % (serial, realms))

    return realms


def getTokenInRealm(realm, active=True):
    '''
    This returns the number of tokens in one realm.

    You can either query only active token or also disabled tokens.
    '''
    if active:
        sqlQuery = Session.query(TokenRealm, Realm, Token).filter(and_(
                            TokenRealm.realm_id == Realm.id,
                            Realm.name == u'' + realm,
                            Token.LinOtpIsactive == True,
                            TokenRealm.token_id == Token.LinOtpTokenId)).count()
    else:
        sqlQuery = Session.query(TokenRealm, Realm).filter(and_(
                            TokenRealm.realm_id == Realm.id,
                            Realm.name == realm)).count()
    return sqlQuery

def getTokenNumResolver(resolver=None, active=True):
    '''
    This returns the number of the (active) tokens
    if no resolver is passed, the overall token number is returned,
    if a resolver is passed, the token number within this resolver is returned

    if active is set to false, ALL tokens are returned
    '''
    if resolver is None:
        if active:
            sqlQuery = Session.query(Token).filter(Token.LinOtpIsactive == True).count()
        else:
            sqlQuery = Session.query(Token).count()
        return sqlQuery
    else:
        # in the database could be tokens of ResolverClass:
        #    useridresolver. or useridresolveree.
        # so we have to make sure
        # - there is no 'useridresolveree' in the searchterm and
        # - there is a wildcard search: second replace
        # Remark: when the token is loaded the response to the
        # resolver class is adjusted

        resolver = resolver.resplace('useridresolveree.', 'useridresolver.')
        resolver = resolver.resplace('useridresolver.', 'useridresolver%.')

        if active:
            sqlQuery = Session.query(Token).filter(
                and_(Token.LinOtpIdResClass.like(resolver),
                     Token.LinOtpIsactive == True)).count()
        else:
            sqlQuery = Session.query(Token).filter(
                Token.LinOtpIdResClass.like(resolver)).count()
        return sqlQuery

def getAllTokenUsers():
    '''
        return a list of all users
    '''
    users = {}
    sqlQuery = Session.query(Token)
    for token in sqlQuery:
        userInfo = {}

        log.debug("[getAllTokenUsers] user serial (serial): %r" % token.LinOtpTokenSerialnumber)

        serial = token.LinOtpTokenSerialnumber
        userId = token.LinOtpUserid
        resolver = token.LinOtpIdResolver
        resolverC = token.LinOtpIdResClass

        if len(userId) > 0 and len(resolver) > 0:
            userInfo = getUserInfo(userId, resolver, resolverC)

        if len(userId) > 0 and len(userInfo) == 0:
            userInfo['username'] = u'/:no user info:/'

        if len(userInfo) > 0:
            users[serial] = userInfo

    return users


def getTokens4UserOrSerial(user=None, serial=None, token_type=None,
                           _class=True):
    tokenList = []
    tokenCList = []
    tok = None

    if serial is None and user is None:
        log.warning("[getTokens4UserOrSerial] missing user or serial")
        return tokenList

    if (serial is not None):
        log.debug("[getTokens4UserOrSerial] getting"
                  " token object with serial: %r" % serial)
        #  SAWarning of non unicode type
        serial = linotp.lib.crypt.uencode(serial)
        sconditions = ()
        if token_type:
            sconditions += (and_(func.lower(Token.LinOtpTokenType) ==
                                 token_type.lower()),)

        if '*' in serial:
            serial = serial.replace('*', '%')
            sconditions += (and_(Token.LinOtpTokenSerialnumber.like(serial)),)
        else:
            sconditions += (and_(Token.LinOtpTokenSerialnumber == serial),)

        # finally run the query on token serial
        condition = and_(*sconditions)
        sqlQuery = Session.query(Token).filter(condition)

        for token in sqlQuery:
            log.debug("[getTokens4UserOrSerial] user "
                      "serial (serial): %r" % token.LinOtpTokenSerialnumber)
            tokenList.append(token)

    if user is not None:
        log.debug("[getTokens4UserOrSerial] getting token object 4 user: %r"
                  % user)

        if not user.isEmpty() and user.login:
            users = []

            # getUserId triggers the lookup of the resolvers
            # which could then be used for multiple users in realm
            getUserId(user)
            for resolverClass, uid in user.resolverUid.items():
                users.append((uid, resolverClass))

            for lookup_user in users:
                (uid, resolverClass) = lookup_user

                # in the database could be tokens of ResolverClass:
                #    useridresolver. or useridresolveree.
                # so we have to make sure
                # - there is no 'useridresolveree' in the searchterm and
                # - there is a wildcard search: second replace
                # Remark: when the token is loaded the response to the
                # resolver class is adjusted

                uconditions = ()

                resolverClass = resolverClass.replace('useridresolveree.',
                                                      'useridresolver.')
                resolverClass = resolverClass.replace('useridresolver.',
                                                      'useridresolver%.')

                uconditions += (and_(model.Token.LinOtpUserid == uid),)
                uconditions += (and_(model.Token.LinOtpIdResClass.like(resolverClass)),)

                if token_type:
                    uconditions += (and_(func.lower(Token.LinOtpTokenType) ==
                                         token_type.lower()),)

                condition = and_(*uconditions)
                sqlQuery = Session.query(Token).filter(condition)

                for token in sqlQuery:
                    # we have to check that the token is in the same realm as the user
                    t_realms = token.getRealmNames()
                    u_realm = user.getRealm()
                    if u_realm != '*':
                        if len(t_realms) > 0 and len(u_realm) > 0:
                            if u_realm.lower() not in t_realms:
                                log.debug("user realm and token realm missmatch %r::%r"
                                      % (u_realm, t_realms))
                                continue
    
                    log.debug("[getTokens4UserOrSerial] user serial (user): %r"
                              % token.LinOtpTokenSerialnumber)
                    tokenList.append(token)


    if _class is True:
        for tok in tokenList:
            tokenCList.append(createTokenClassObject(tok))
        return tokenCList
    else:
        return tokenList

def setDefaults(token):
    #  set the defaults
    token.LinOtpOtpLen = int(getFromConfig("DefaultOtpLen", 6))
    token.LinOtpCountWindow = int(getFromConfig("DefaultCountWindow", 15))
    token.LinOtpMaxFail = int(getFromConfig("DefaultMaxFailCount", 15))
    token.LinOtpSyncWindow = int(getFromConfig("DefaultSyncWindow", 1000))

    token.LinOtpTokenType = u"HMAC"


def tokenExist(serial):
    '''
    returns true if the token exists
    '''
    log.debug("[tokenExist] checking if Token %r exists" % serial)
    if serial:
        toks = getTokens4UserOrSerial(None, serial)
        return (len(toks) > 0)
    else:
        # If we have no serial we return false anyway!
        log.debug("[tokenExist] returning false anyway")
        return False



def get_token_owner(token):
    """
    provide the owner as a user object for a given tokenclass obj

    :param token: tokenclass object
    :return: user object
    """

    if token is None:
        # for backward compatibility, we return here an empty user
        return User()

    _ = context['translate']
    serial = token.getSerial()

    log.debug("[get_token_owner] token found: %r" % token)
    uid, resolver, resolverClass = token.getUser()

    userInfo = getUserInfo(uid, resolver, resolverClass)
    log.debug("[get_token_owner] got the owner %r, %r, %r"
               % (uid, resolver, resolverClass))

    if not userInfo:
        return User()

    realms = getUserRealms(User(uid, "", resolverClass.split(".")[-1]))
    log.debug("[get_token_owner] got this realms: %r" % realms)

    # if there are several realms, than we need to find out, which one!
    if len(realms) > 1:
        t_realms = getTokenRealms(serial)
        common_realms = list(set(realms).intersection(t_realms))
        if len(common_realms) > 1:
            raise Exception(_("get_token_owner: The user %s/%s and the token"
                              " %s is located in several realms: "
                              "%s!" % (uid, resolverClass, serial, common_realms)))
        realm = common_realms[0]
    elif len(realms) == 0:
        raise Exception(_("get_token_owner: The user %s in the resolver"
                          " %s for token %s could not be found in any "
                          "realm!" % (uid, resolverClass, serial)))
    else:
        realm = realms[0]

    user = User()
    user.realm = realm
    user.login = userInfo.get('username')
    user.resolver_config_identifier = resolverClass
    if userInfo:
        user.info = userInfo

    log.debug("[get_token_owner] found the user %r and the realm %r as "
              "owner of token %r" % (user.login, user.realm, serial))

    return user

def getTokenType(serial):
    '''
    Returns the tokentype of a given serial number

    :param serial: the serial number of the to be searched token
    '''
    log.debug("[getTokenType] getting token type for serial: %r" % serial)
    toks = getTokens4UserOrSerial(None, serial, _class=False)

    typ = ""
    for tok in toks:
        typ = tok.LinOtpTokenType

    log.debug("[getTokenType] the token is of type: %r" % typ)

    return typ

def add_last_accessed_info(list_of_tokenlist):
    """
    if token_last_access is defined in the config, add this to the token info
    """

    token_last_access = getFromConfig('token.last_access', None)
    if not token_last_access:
        return

    stampTokens = []
    for token_list in list_of_tokenlist:
        stampTokens.extend(token_list)

    now = datetime.datetime.now()
    acces_info = now.strftime(token_last_access)
    for token in stampTokens:
        token.addToTokenInfo('last_access', acces_info)

    return


def get_multi_otp(serial, count=0, epoch_start=0, epoch_end=0, curTime=None):
    '''
    This function returns a list of OTP values for the given Token.
    Please note, that this controller needs to be activated and
    that the tokentype needs to support this function.

    method
        get_multi_otp    - get the list of OTP values

    parameter
        serial            - the serial number of the token
        count             - number of the <count> next otp values (to be used with event or timebased tokens)
        epoch_start       - unix time start date (used with timebased tokens)
        epoch_end         - unix time end date (used with timebased tokens)
        curTime          - used for selftest

    return
        dictionary of otp values
    '''
    ret = {"result" : False}
    log.debug("[get_multi_otp] retrieving OTP values for token %r" % serial)
    toks = getTokens4UserOrSerial(None, serial)

    if len(toks) > 1:
        log.error("[get_multi_otp] multiple tokens with serial %r found - cannot get OTP!" % serial)
        raise TokenAdminError("multiple tokens found - cannot get OTP!", id=1201)

    if len(toks) == 0:
        log.warning("[getOTP] there is no token with serial %r" % serial)
        ret["error"] = "No Token with serial %s found." % serial

    if len(toks) == 1:
        token = toks[0]
        log.debug("[get_multi_otp] getting multiple otp values for token %r. curTime=%r" % (token, curTime))
        # if the token does not support getting the OTP value, res==False is returned
        (res, error, otp_dict) = token.get_multi_otp(count=count, epoch_start=epoch_start, epoch_end=epoch_end, curTime=curTime)
        log.debug("[get_multi_otp] received %r, %r, %r" % (res, error, otp_dict))

        if res is True:
            ret = otp_dict
            ret["result"] = True
        else:
            ret["error"] = error

    return ret

def getOtp(serial, curTime=None):
    '''
    This function returns the current OTP value for a given Token.
    Please note, that this controller needs to be activated and
    that the tokentype needs to support this function.

    method
        getOtp    - get the current OTP value

    parameter
        serial    - serialnumber for token
        curTime   - used for self test

    return
        tuple with (res, pin, otpval, passw)

    '''
    log.debug("[getOtp] retrieving OTP value for token %r" % serial)
    toks = getTokens4UserOrSerial(None, serial)

    if len(toks) > 1:
        raise TokenAdminError("multiple tokens found - cannot get OTP!", id=1101)

    if len(toks) == 0:
        log.warning("[getOTP] there is no token with serial %r" % serial)
        return (-1, "", "", "")

    if len(toks) == 1:
        token = toks[0]
        # if the token does not support getting the OTP value, a -2 is returned.
        return token.getOtp(curTime=curTime)


def setPin(pin, user, serial, param=None):
    '''
    set the PIN
    '''
    if param is None:
        param = {}

    log.debug("[setPin] calling setPin.")

    if (user is None) and (serial is None):
        log.warning("[setPin] Parameter user or serial required!")
        raise ParameterError("Parameter user or serial required!", id=1212)

    if (user is not None):
        log.info("[setPin] setting Pin for user %r@%r" % (user.login, user.realm))
    if (serial is not None):
        log.info("[setPin] setting Pin for token with serial %r" % serial)

    tokenList = getTokens4UserOrSerial(user, serial)

    for token in tokenList:
        token.addToSession(Session)
        token.setPin(pin, param)

    return len(tokenList)


# local

###############################################################################
#  LinOtpTokenPinUser
###############################################################################
def setPinUser(userPin, serial):

    user = None

    if serial is None:
        log.warning("[setPinUser] Parameter serial required!")
        raise ParameterError("Parameter 'serial' is required!", id=1212)

    log.debug("[setPin] setting Pin for serial %r" % serial)
    tokenList = getTokens4UserOrSerial(user, serial)

    for token in tokenList:
        token.addToSession(Session)
        token.setUserPin(userPin)

    return len(tokenList)

###############################################################################
#  LinOtpTokenPinSO
###############################################################################
def setPinSo(soPin, serial):
    user = None

    if serial is None:
        log.warning("[setPinSo] Parameter serial required!")
        raise ParameterError("Parameter 'serial' is required!", id=1212)

    log.debug("[setPinSo] setting Pin for serial %r" % serial)
    tokenList = getTokens4UserOrSerial(user, serial)

    for token in tokenList:
        token.addToSession(Session)
        token.setSoPin(soPin)

    return len(tokenList)

def resetToken(user=None, serial=None):

    if (user is None) and (serial is None):
        log.warning("[resetToken] Parameter serial or user required!")
        raise ParameterError("Parameter user or serial required!", id=1212)

    log.debug("[resetToken] reset token with serial %r" % serial)
    tokenList = getTokens4UserOrSerial(user, serial)

    for token in tokenList:
        token.addToSession(Session)
        token.reset()

    return len(tokenList)


def _gen_serial(prefix, tokennum, min_len=8):
    '''
    helper to create a hex digit string

    :param prefix: the prepended prefix like LSGO
    :param tokennum: the token number counter (int)
    :param min_len: int, defining the length of the hex string
    :return: hex digit string
    '''
    h_serial = ''
    num_str = '%.4d' % tokennum
    h_len = min_len - len(num_str)
    if h_len > 0:
        h_serial = binascii.hexlify(os.urandom(h_len)).upper()[0:h_len]
    return "%s%s%s" % (prefix, num_str, h_serial)


def genSerial(tokenType=None, prefix=None):
    '''
    generate a serial number similar to the one generated in the manage web gui

    :param tokenType: the token type prefix is done by a lookup on the tokens
    :return: serial number
    '''
    if tokenType is None:
        tokenType = 'LSUN'

    tokenprefixes = config['tokenprefixes']

    if prefix is None:
        prefix = tokenType.upper()
        if tokenType.lower() in tokenprefixes:
            prefix = tokenprefixes.get(tokenType.lower())

    #  now search the number of ttypes in the token database
    tokennum = Session.query(Token).filter(
                    Token.LinOtpTokenType == u'' + tokenType).count()

    serial = _gen_serial(prefix, tokennum + 1)

    #  now test if serial already exists
    while True:
        numtokens = Session.query(Token).filter(
                        Token.LinOtpTokenSerialnumber == u'' + serial).count()
        if numtokens == 0:
            #  ok, there is no such token, so we're done
            break
        #  else - rare case:
        #  we add the numtokens to the number of existing tokens with serial
        serial = _gen_serial(prefix, tokennum + numtokens)

    return serial

def getTokenConfig(tok, section=None):
    '''
    getTokenConfig - return the config definition
                     of a dynamic token

    :param tok: token type (shortname)
    :type  tok: string

    :param section: subsection of the token definition - optional
    :type   section: string

    :return: dict - if nothing found an empty dict
    :rtype:  dict
    '''
    res = {}

    g = config['pylons.app_globals']
    tokenclasses = g.tokenclasses

    if tok in tokenclasses.keys():
        tclass = tokenclasses.get(tok)
        tclt = newToken(tclass)
        # check if we have a policy in the token definition
        if hasattr(tclt, 'getClassInfo'):
            res = tclt.getClassInfo(section, ret={})

    return res

# eof #########################################################################
