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
""" validation processing logic"""

import logging
import linotp

import linotp.lib.policy

from pylons import config

from linotp.lib.challenges import Challenges
from linotp.lib.error import ParameterError, UserError
from linotp.lib.realm import getDefaultRealm
from linotp.lib.resolver import getResolverObject
from linotp.lib.token import TokenHandler
from linotp.lib.user import (User, getUserId, getUserInfo)
from linotp.lib.util import modhex_decode

log = logging.getLogger(__name__)


def check_pin(token, passw, user=None, options=None):
    """
    check the provided pin w.r.t. the policy definition

    :param token: the token to be checked
    :param passw: the to be checked pass
    :param user: if otppin==1, this is the user, which resolver should
                 be checked
    :param options: the optional request parameters

    :return: boolean, if pin matched True
    """
    res = False
    context = token.context
    pin_policies = linotp.lib.policy.get_pin_policies(user, context=context)

    if 1 in pin_policies:
        # We check the Users Password as PIN
        log.debug('pin policy=1: checking the users password as pin')
        if (user is None or not user.login):
            log.info('- fail for pin policy == 1 with user = None')
            return False

        (uid, _resolver, resolver_class) = getUserId(user)

        r_obj = getResolverObject(resolver_class)
        if r_obj.checkPass(uid, passw):
            log.debug('[__checkToken] Successfully authenticated user %r.'
                      % uid)
            res = True
        else:
            log.info('[__checkToken] user %r failed to auth.' % uid)

    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug('[__checkToken] pin policy=2: checking no pin')
        if len(passw) == 0:
            res = True
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug('[__checkToken] pin policy=0: checkin the PIN')
        res = token.checkPin(passw, options=options)

    return res


def check_otp(token, otpval, options=None):
    """
    check the otp value

    :param otpval: the to be checked otp value
    :param options: the additional request parameters

    :return: result of the otp check, which is
            the matching otpcounter or -1 if not valid
    """

    log.debug('entering function check_otp()')
    log.debug('token  : %r' % token)
    # This is only the OTP value, not the OTP PIN
    log.debug('OtpVal : %r' % otpval)

    res = -1
    counter = token.getOtpCount()
    window = token.getOtpCountWindow()

    res = token.checkOtp(otpval, counter, window, options=options)
    return res

def split_pin_otp(token, passw, user=None, options=None):
    """
    split the pin and the otp fron the given password

    :param passw: the to be splitted password
    :param options: currently not used, but might be forwarded to the
                    token.splitPinPass
    :return: tuple of (split status, pin and otpval)
    """
    context = token.context
    pin_policies = linotp.lib.policy.get_pin_policies(user, context=context)

    policy = 0

    if 1 in pin_policies:
        log.debug('pin policy=1: checking the users password as pin')
        # split the passw into password and otp value
        (pin, otp) = token.splitPinPass(passw)
        policy = 1
    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug('pin policy=2: checking no pin')
        (pin, otp) = ('', passw)
        policy = 2
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug('pin policy=0: checkin the PIN')
        (pin, otp) = token.splitPinPass(passw)

    res = policy
    return (res, pin, otp)


class ValidationHandler(object):

    def __init__(self, context):
        self.context = context

    def checkSerialPass(self, serial, passw, options=None, user=None):
        """
        This function checks the otp for a given serial

        :attention: the parameter user must be set, as the pin policy==1 will
                    verify the user pin
        """

        log.debug('checking for serial %r' % serial)
        tokenList = linotp.lib.token.getTokens4UserOrSerial(
            None, serial, context=self.context)

        if passw is None:
            # other than zero or one token should not happen, as serial is unique
            if len(tokenList) == 1:
                theToken = tokenList[0]
                tok = theToken.token
                realms = tok.getRealmNames()
                if realms is None or len(realms) == 0:
                    realm = getDefaultRealm()
                elif len(realms) > 0:
                    realm = realms[0]
                userInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver,
                                       tok.LinOtpIdResClass)
                user = User(login=userInfo.get('username'), realm=realm)
                user.info = userInfo

                if theToken.is_challenge_request(passw, user, options=options):
                    (res, opt) = Challenges.create_challenge(
                        theToken, self.context, options)
                else:
                    raise ParameterError('Missing parameter: pass', id=905)

            else:
                raise Exception('No token found: '
                                'unable to create challenge for %s' % serial)

        else:
            log.debug('checking len(pass)=%r for serial %r' %
                      (len(passw), serial))

            (res, opt) = self.checkTokenList(
                tokenList, passw, user=user, options=options)

        return (res, opt)

    def checkUserPass(self, user, passw, options=None):
        """
        :param user: the to be identified user
        :param passw: the identifiaction pass
        :param options: optional parameters, which are provided
                    to the token checkOTP / checkPass

        :return: tuple of True/False and optional information
        """

        log.debug('entering function checkUserPass(%r)'
                  % user.login)
        # the upper layer will catch / at least should ;-)

        opt = None
        serial = None
        resolverClass = None
        uid = None
        audit = self.context['audit']

        if user is not None and (user.isEmpty() == False):
            # the upper layer will catch / at least should
            try:
                (uid, _resolver, resolverClass) = getUserId(user)
            except:
                pass_on = self.context.get('Config').get(
                                            'linotp.PassOnUserNotFound', False)
                if pass_on and 'true' == pass_on.lower():
                    audit['action_detail'] = (
                                        'authenticated by PassOnUserNotFound')
                    return (True, opt)
                else:
                    audit['action_detail'] = 'User not found'
                    return (False, opt)

        tokenList = linotp.lib.token.getTokens4UserOrSerial(user, serial,
                                                            context=self.context)

        if len(tokenList) == 0:
            audit['action_detail'] = 'User has no tokens assigned'

            # here we check if we should to autoassign and try to do it
            log.debug('about to check auto_assigning')

            th = TokenHandler(context=self.context)
            auto_assign_return = th.auto_assignToken(passw, user)
            if auto_assign_return is True:
                # We can not check the token, as the OTP value is already used!
                # but we will auth the user....
                return (True, opt)

            auto_enroll_return, opt = th.auto_enrollToken(passw, user,
                                                            options=options)
            if auto_enroll_return is True:
                # we always have to return a false, as
                # we have a challenge tiggered
                return (False, opt)

            pass_on = self.context.get('Config').get('linotp.PassOnUserNoToken',
                                                         False)
            if pass_on and 'true' == pass_on.lower():
                audit['action_detail'] = 'authenticated by PassOnUserNoToken'
                return (True, opt)

            #  Check if there is an authentication policy passthru
            from linotp.lib.policy import get_auth_passthru
            if get_auth_passthru(user, context=self.context):
                log.debug('user %r has no token. Checking for '
                          'passthru in realm %r' % (user.login, user.realm))
                y = getResolverObject(resolverClass)
                audit['action_detail'] = 'Authenticated against Resolver'
                if y.checkPass(uid, passw):
                    return (True, opt)

            #  Check if there is an authentication policy passOnNoToken
            from linotp.lib.policy import get_auth_passOnNoToken
            if get_auth_passOnNoToken(user, context=self.context):
                log.info('user %r has not token. PassOnNoToken'
                         ' set - authenticated!')
                audit['action_detail'] = (
                    'Authenticated by passOnNoToken policy')
                return (True, opt)

            return (False, opt)

        if passw is None:
            raise ParameterError(u"Missing parameter:pass", id=905)

        (res, opt) = self.checkTokenList(
            tokenList, passw, user, options=options)
        log.debug('return of __checkTokenList: %r ' % (res,))

        return (res, opt)

    def checkTokenList(self, tokenList, passw, user=User(), options=None):
        """
        identify a matching token and test, if the token is valid, locked ..
        This function is called by checkSerialPass and checkUserPass to

        :param tokenList: list of identified tokens
        :param passw: the provided passw (mostly pin+otp)
        :param user: the identified use - as class object
        :param options: additonal parameters, which are passed to the token

        :return: tuple of boolean and optional response
        """
        log.debug("[__checkTokenList] checking tokenlist: %r" % tokenList)
        reply = None

        tokenclasses = config['tokenclasses']

        #  add the user to the options, so that every token could see the user
        if not options:
            options = {}

        options['user'] = user

        # if there has been one token in challenge mode, we only handle challenges

        # if we got a validation against a sub_challenge, we extend this to
        # be a validation to all challenges of the transaction id
        import copy
        check_options = copy.deepcopy(options)
        state = check_options.get('state', check_options.get('transactionid', ''))
        if state and '.' in state:
            transid = state.split('.')[0]
            if 'state' in check_options:
                check_options['state'] = transid
            if 'transactionid' in check_options:
                check_options['transactionid'] = transid

        challenge_tokens = []
        pin_matching_tokens = []
        invalid_tokens = []
        valid_tokens = []
        related_challenges = []

        # we have to preserve the result / reponse for token counters
        validation_results = {}

        for token in tokenList:
            log.debug('[__checkTokenList] Found user with loginId %r: %r:\n' % (
                                        token.getUserId(), token.getSerial()))

            # preselect: the token must be in the same realm as the user
            if user is not None:
                t_realms = token.token.getRealmNames()
                u_realm = user.getRealm()
                if (len(t_realms) > 0 and len(u_realm) > 0 and
                        u_realm.lower() not in t_realms):
                    continue
            audit = {}
            audit.update({'serial': token.getSerial(),
                          'token_type': token.getType(),
                          'weight': 0})

            #  check if the token is the list of supported tokens
            #  if not skip to the next token in list
            typ = token.getType()
            if typ.lower() not in tokenclasses:
                log.error('token typ %r not found in tokenclasses: %r' %
                          (typ, tokenclasses))
                audit['action_detail'] = "Unknown Token type"
                continue

            if not token.isActive():
                audit['action_detail'] = "Token inactive"
                continue
            if token.getFailCount() >= token.getMaxFailCount():
                audit['action_detail'] = "Failcounter exceeded"
                continue
            if not token.check_auth_counter():
                audit['action_detail'] = "Authentication counter exceeded"
                continue
            if not token.check_validity_period():
                audit['action_detail'] = "validity period mismatch"
                continue

            # start the token validation
            try:
                # are there outstanding challenges
                challenges = token.get_token_challenges(check_options)
                (ret, reply) = token.check_token(
                    passw, user, options=check_options, challenges=challenges)
            except Exception as exx:
                # in case of a failure during checking token, we log the error
                # and continue with the next one
                log.exception("checking token %r failed: %r" % (token, exx))
                ret = -1
                reply = "%r" % exx
                continue
            finally:
                validation_results[token.getSerial()] = (ret, reply)

            (cToken, pToken, iToken, vToken) = token.get_verification_result()
            related_challenges.extend(token.related_challenges)

            challenge_tokens.extend(cToken)
            pin_matching_tokens.extend(pToken)
            invalid_tokens.extend(iToken)
            valid_tokens.extend(vToken)

        # end of token verification loop

        # if there are related / sub challenges, we have to call their janitor
        Challenges.handle_related_challenge(related_challenges, self.context)

        # now we finalize the token validation result
        fh = FinishTokens(valid_tokens,
                          challenge_tokens,
                          pin_matching_tokens,
                          invalid_tokens,
                          validation_results,
                          user, options,
                          context=self.context
                          )

        (res, reply) = fh.finish_checked_tokens()

        # add to all tokens the last accessd time stamp
        linotp.lib.token.add_last_accessed_info(
            [valid_tokens, pin_matching_tokens, challenge_tokens, valid_tokens])

        log.debug("Number of valid tokens found "
                  "(validTokenNum): %d" % len(valid_tokens))

        return (res, reply)

    def checkYubikeyPass(self, passw):
        """
        Checks the password of a yubikey in Yubico mode (44,48), where
        the first 12 or 16 characters are the tokenid

        :param passw: The password that consist of the static yubikey prefix
                        and the otp
        :type passw: string

        :return: True/False and the User-Object of the token owner
        :rtype: dict
        """

        audit = self.context['audit']
        opt = None
        res = False

        tokenList = []

        # strip the yubico OTP and the PIN
        modhex_serial = passw[:-32][-16:]
        try:
            serialnum = "UBAM" + modhex_decode(modhex_serial)
        except TypeError as exx:
            log.error("Failed to convert serialnumber: %r" % exx)
            return res, opt

        #  build list of possible yubikey tokens
        serials = [serialnum]
        for i in range(1, 3):
            serials.append("%s_%s" % (serialnum, i))

        for serial in serials:
            tokens = linotp.lib.token.getTokens4UserOrSerial(
                                        serial=serial, context=self.context)
            tokenList.extend(tokens)

        if len(tokenList) == 0:
            audit['action_detail'] = ('The serial %s could not be found!'
                                        % serialnum)
            return res, opt

        # FIXME if the Token has set a PIN and the User does not want to enter
        # the PIN for authentication, we need to do something different here...
        #  and avoid PIN checking in __checkToken.
        #  We could pass an "option" to __checkToken.
        (res, opt) = self.checkTokenList(tokenList, passw)

        # Now we need to get the user
        if res is not False and 'serial' in audit:
            serial = audit.get('serial', None)
            if serial is not None:
                user = self.getTokenOwner(serial)
                audit['user'] = user.login
                audit['realm'] = user.realm
                opt = {'user': user.login, 'realm': user.realm}

        return res, opt

class FinishTokens(object):

    def __init__(self, valid_tokens, challenge_tokens,
                        pin_matching_tokens, invalid_tokens,
                        validation_results,
                        user, options,
                        context=None):
        """
        create the finalisation object, that finishes the token processing

        :param valid_tokens: list of valid tokens
        :param challenge_tokens: list of the tokens, that trigger a challenge
        :param pin_matching_tokens: list of tokens with a matching pin
        :param invalid_tokens: list of the invalid tokens
        :param validation_results: dict of the verification response
        :param user: the requesting user
        :param options: request options - additional parameters
        """

        self.valid_tokens = valid_tokens
        self.challenge_tokens = challenge_tokens
        self.pin_matching_tokens = pin_matching_tokens
        self.invalid_tokens = invalid_tokens
        self.validation_results = validation_results
        self.user = user
        self.options = options
        self.context = context

    def finish_checked_tokens(self):
        """
        main entry to finalise the involved tokens
        """

        # do we have any valid tokens?
        if self.valid_tokens:
            (ret, reply, detail) = self.finish_valid_tokens()
            self.reset_failcounter(self.valid_tokens +
                                   self.invalid_tokens +
                                   self.pin_matching_tokens +
                                   self.challenge_tokens)

            self.create_audit_entry(detail, self.valid_tokens)
            return ret, reply

        # next handle the challenges
        if self.challenge_tokens:
            (ret, reply, detail) = self.finish_challenge_token()
            # do we have to increment the counter to prevent a replay???
            # self.increment_counters(self.challenge_tokens)
            self.create_audit_entry(detail, self.challenge_tokens)
            return ret, reply

        failed_tokens = self.pin_matching_tokens + self.invalid_tokens
        if self.user:
            log.warning("user %r@%r failed to auth."
                        % (self.user.login, self.user.realm))
        elif failed_tokens:
            log.warning("serial %r failed to auth."
                        % failed_tokens[0].getSerial())
        else:
            log.warning("generic authentication failure.")

        if self.pin_matching_tokens:
            (ret, reply, detail) = self.finish_pin_matching_tokens()
            # in case of pin matching, we have to treat as well the invalid
            self.increment_failcounters(self.pin_matching_tokens)
            self.finish_invalid_tokens()

            # check for the global settings, if we increment in wrong pin
            incOnFalsePin = self.context.get(
                "linotp.FailCounterIncOnFalsePin", "True")
            if incOnFalsePin.strip().lower() == 'true':
                self.increment_failcounters(self.invalid_tokens)
            self.create_audit_entry(detail, self.pin_matching_tokens)
            return ret, reply

        if self.invalid_tokens:
            (ret, reply, detail) = self.finish_invalid_tokens()
            self.increment_failcounters(self.invalid_tokens)

            self.create_audit_entry(detail, self.invalid_tokens)
            return ret, reply

        # if there is no token left, we hend up here
        self.create_audit_entry("no token found", [])
        return False, None

    def finish_valid_tokens(self):
        """
        processing of the valid tokens
        """
        valid_tokens = self.valid_tokens
        validation_results = self.validation_results
        user = self.user

        if len(valid_tokens) == 1:
            token = valid_tokens[0]
            if user:
                action_detail = ("user %r@%r successfully authenticated."
                                 % (user.login, user.realm))
            else:
                action_detail = ("serial %r successfully authenticated."
                                 % token.getSerial())

            log.info(action_detail)

            # there could be a match in the window ahead,
            # so we need the last valid counter here
            (counter, _reply) = validation_results[token.getSerial()]
            token.setOtpCount(counter + 1)
            token.statusValidationSuccess()
            if token.getFromTokenInfo('count_auth_success_max', default=None):
                auth_count = token.get_count_auth_success()
                token.set_count_auth_success(auth_count + 1)
            return (True, None, action_detail)

        else:
            # we have to set the matching counter to prevent replay one one
            # single token
            for token in valid_tokens:
                (res, _reply) = validation_results[token.getSerial()]
                token.setOtpCount(res)

            self.context['audi']['action_detail'] = "Multiple valid tokens found!"
            if user:
                log.error("[__checkTokenList] multiple token match error: "
                          "Several Tokens matching with the same OTP PIN "
                          "and OTP for user %r. Not sure how to auth",
                          user.login)
            raise UserError("multiple token match error", id=-33)


    def finish_challenge_token(self):
        """
        processing of the challenge tokens
        """
        challenge_tokens = self.challenge_tokens
        options = self.options
        if not options:
            options = {}

        action_detail = 'challenge created'

        if len(challenge_tokens) == 1:
            challenge_token = challenge_tokens[0]
            _res, reply = Challenges.create_challenge(
                                challenge_token, self.context, options=options)
            return (False, reply, action_detail)

        # processing of multiple challenges
        else:
            # for each token, who can submit a challenge, we have to
            # create the challenge. To mark the challenges as depending
            # the transaction id will have an id that all sub transaction share
            # and a postfix with their enumaration. Finally the result is
            # composed by the top level transaction id and the message
            # and below in a dict for each token a challenge description -
            # the key is the token type combined with its token serial number
            all_reply = {'challenges': {}}
            challenge_count = 0
            transactionid = ''
            challenge_id = ""
            for challenge_token in challenge_tokens:
                challenge_count += 1
                id_postfix = ".%02d" % challenge_count
                if transactionid:
                    challenge_id = "%s%s" % (transactionid, id_postfix)

                (_res, reply) = Challenges.create_challenge(
                    challenge_token,
                    self.context,
                    options=options,
                    challenge_id=challenge_id,
                    id_postfix=id_postfix
                )
                transactionid = reply.get('transactionid').rsplit('.')[0]

                # add token type and serial to ease the type specific processing
                reply['linotp_tokentype'] = challenge_token.type
                reply['linotp_tokenserial'] = challenge_token.getSerial()
                key = challenge_token.getSerial()
                all_reply['challenges'][key] = reply

            # finally add the root challenge response with top transaction id
            # and message, that indicates that 'multiple challenges have been
            # submitted
            all_reply['transactionid'] = transactionid
            all_reply['message'] = "Multiple challenges submitted."

            log.debug("Multiple challenges submitted: %d",
                      len(challenge_tokens))

            return (False, all_reply, action_detail)

    def finish_pin_matching_tokens(self):
        """
            check, if there have been some tokens
            where the pin matched (but OTP failed
            and increment only these
        """
        pin_matching_tokens = self.pin_matching_tokens
        action_detail = "wrong otp value"

        for tok in pin_matching_tokens:
            tok.statusValidationFail()
            tok.inc_count_auth()

        return (False, None, action_detail)

    def finish_invalid_tokens(self):
        """
        """
        invalid_tokens = self.invalid_tokens
        user = self.user

        for tok in invalid_tokens:
            tok.statusValidationFail()

        import linotp.lib.policy
        pin_policies = linotp.lib.policy.get_pin_policies(
                                            user, context=self.context) or []

        if 1 in pin_policies:
            action_detail = "wrong user password -1"
        else:
            action_detail = "wrong otp pin -1"

        return (False, None, action_detail)

    @staticmethod
    def reset_failcounter(all_tokens):
        for token in all_tokens:
            token.reset()

    @staticmethod
    def increment_counters(all_tokens, reset=True):
        for token in all_tokens:
            token.incOtpCounter(reset=reset)

    @staticmethod
    def increment_failcounters(all_tokens):
        for token in all_tokens:
            token.incOtpFailCounter()

    def create_audit_entry(self, action_detail, tokens):
        """
        setting global audit entry

        :param tokens:
        :param action_detail:
        """
        audit = self.context['audit']
        audit['action_detail'] = action_detail

        if len(tokens) == 1:
            audit['serial'] = tokens[0].getSerial()
            audit['token_type'] = tokens[0].getType()
        else:
            # no or multiple tokens
            audit['serial'] = ''
            audit['token_type'] = ''
        return
# eof###########################################################################
