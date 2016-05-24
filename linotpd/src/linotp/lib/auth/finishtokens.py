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
from linotp.lib.challenges import Challenges
from linotp.lib.context import request_context as context
from linotp.lib.error import UserError
from linotp.lib.policy import supports_offline
import logging


log = logging.getLogger(__name__)


class FinishTokens(object):

    def __init__(self,
                 valid_tokens, challenge_tokens,
                 pin_matching_tokens, invalid_tokens,
                 validation_results, user, options,
                 audit_entry=None):
        """
        create the finalisation object, that finishes the token processing

        :param valid_tokens: list of valid tokens
        :param challenge_tokens: list of the tokens, that trigger a challenge
        :param pin_matching_tokens: list of tokens with a matching pin
        :param invalid_tokens: list of the invalid tokens
        :param validation_results: dict of the verification response
        :param user: the requesting user
        :param options: request options - additional parameters
        :param audit_entry: audit_entry reference
        """

        self.valid_tokens = valid_tokens
        self.challenge_tokens = challenge_tokens
        self.pin_matching_tokens = pin_matching_tokens
        self.invalid_tokens = invalid_tokens

        self.validation_results = validation_results

        self.user = user
        self.options = options
        self.audit_entry = audit_entry or {}

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

        # if there is no token left, we end up here
        if not (self.pin_matching_tokens + self.invalid_tokens):
            self.create_audit_entry(action_detail="no token found!",
                                    tokens=[])
            log.info("no valid token found: %r" % self.audit_entry)
            return False, None

        if self.user:
            log.warning("user %r@%r failed to auth."
                        % (self.user.login, self.user.realm))
        else:
            log.warning("serial %r failed to auth."
                        % (self.pin_matching_tokens +
                           self.invalid_tokens)[0].getSerial())

        if self.invalid_tokens:
            (ret, reply, detail) = self.finish_invalid_tokens()
            self.increment_failcounters(self.invalid_tokens)

            self.create_audit_entry(action_detail=detail,
                                    tokens=self.invalid_tokens)

        if self.pin_matching_tokens:
            (ret, reply, detail) = self.finish_pin_matching_tokens()
            self.increment_failcounters(self.pin_matching_tokens)

            self.create_audit_entry(action_detail=detail,
                                    tokens=self.pin_matching_tokens)

        return ret, reply

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
            # finish as well related open challenges
            Challenges.finish_challenges(token, success=True)

            if token.getFromTokenInfo('count_auth_success_max', default=None):
                auth_count = token.get_count_auth_success()
                token.set_count_auth_success(auth_count + 1)

            detail = None
            auth_info = self.options.get('auth_info', 'False')
            if auth_info.lower() == "true":
                detail = token.getAuthDetail()

            # 1. check if token supports offline at all
            supports_offline_at_all = token.supports_offline_mode

            # 2. check if policy allows to use offline authentication
            if user is not None and user.login and user.realm:
                realms = [user.realm]
            else:
                realms = token.getRealms()

            offline_is_allowed = supports_offline(realms, token)

            # 3. check if parameter 'use_offline' is provided
            use_offline_param = self.options.get('use_offline', 'False')
            use_offline = use_offline_param.lower() == 'true'

            if supports_offline_at_all and \
               offline_is_allowed and \
               use_offline:

                offline_info = token.getOfflineInfo()
                if detail is None:
                    detail = {}

                offline = {'serial': token.getSerial(), 'type': token.type}
                offline['offline_info'] = offline_info

                detail.update({'offline': offline})

            return (True, detail, action_detail)

        else:
            # we have to set the matching counter to prevent replay one one
            # single token
            for token in valid_tokens:
                (res, _reply) = validation_results[token.getSerial()]
                token.setOtpCount(res)

            context['audit']['action_detail'] = "Multiple valid tokens found!"
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
                challenge_token, options=options)
            return (False, reply, action_detail)

        # processing of multiple challenges
        else:
            # for each token, who can submit a challenge, we have to
            # create the challenge. To mark the challenges as depending
            # the transaction id will have an id that all sub transaction share
            # and a postfix with their enumeration. Finally the result is
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
                    options=options,
                    challenge_id=challenge_id,
                    id_postfix=id_postfix
                )
                transactionid = reply.get('transactionid').rsplit('.')[0]

                # add token type and serial to ease the type specific
                # processing
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
            Challenges.finish_challenges(tok, success=False)

        return (False, None, action_detail)

    def finish_invalid_tokens(self):
        """
        """
        invalid_tokens = self.invalid_tokens
        user = self.user

        for tok in invalid_tokens:
            tok.statusValidationFail()
            Challenges.finish_challenges(tok, success=False)

        import linotp.lib.policy
        pin_policies = linotp.lib.policy.get_pin_policies(user) or []

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

    def create_audit_entry(self, action_detail=None, tokens=None):
        """
        setting global audit entry

        :param tokens:
        :param action_detail:
        """

        # get the audit dict from the context
        audit = context['audit']

        # initialize by the given entry
        audit.update(self.audit_entry)

        # and allow overwrite by actual details
        if action_detail:
            audit['action_detail'] = action_detail

        if not tokens:
            audit['serial'] = ''
            audit['token_type'] = ''
        else:
            if len(tokens) == 1:
                audit['serial'] = tokens[0].getSerial()
                audit['token_type'] = tokens[0].getType()
            else:
                # no or multiple tokens
                serials = []
                types = []
                for token in tokens:
                    serials.append(token.getSerial())
                    types.append(token.getType())
                audit['serial'] = ' '.join(serials)[:29]
                audit['token_type'] = ' '.join(types)[:39]

        return
# eof###########################################################################
