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
This file containes the standard token definitions:
- OCRATokenClass

It also contains the base class "TokenClass", that you may use to
define your own tokenclasses.

You can add your own Tokens by adding the modules comma seperated to the
directive 'linotpTokenModules' in the linotp.ini file.

depends on several modules from linotp.lib but also in case of VascoTokenClass
on linotp.lib.ImportOTP.vasco
"""

import binascii
import datetime
import hashlib
import logging
import time

import re

import linotp

from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.crypt import createNonce
from linotp.lib.crypt import decryptPin
from linotp.lib.crypt import encryptPin
from linotp.lib.crypt import kdf2
from linotp.lib.crypt import urandom
from linotp.lib.crypt import SecretObj

from linotp.lib.error import ParameterError
from linotp.lib.error import TokenAdminError
from linotp.lib.policy import get_qrtan_url
from linotp.lib.user import getUserResolverId
from linotp.lib.util import generate_otpkey
from linotp.lib.util import getParam
# TODO: move this as ocra specific methods
from linotp.lib.token import getRolloutToken4User
from linotp.lib.util import normalize_activation_code

from linotp.lib.ocra import OcraSuite
from linotp.model import OcraChallenge

from linotp.model.meta import Session
from linotp.lib.reply import create_img

from linotp.lib.auth.validate import check_pin
from linotp.lib.auth.validate import check_otp
from linotp.lib.auth.validate import split_pin_otp

from sqlalchemy import asc, desc

from linotp.lib.context import request_context as context
from linotp.lib.error import TokenStateError

# needed for ocra token
import urllib

try:
    import json
except ImportError:
    import simplejson as json


optional = True
required = False

log = logging.getLogger(__name__)


class StatefulTokenMixin(object):

    """
    A mixin used by token types that have different
    rollout states (e.g. QRToken and OCRA)
    """

    @property
    def current_state(self):
        """ signifies the current state of the token """

        current_state_id = self.getFromTokenInfo('state')
        return current_state_id

    def ensure_state(self, state_id):
        """
        a barrier method to ensure that a token has a certain state.

        :param state_id: The state the token has to be in
        :raises TokenStateError: If state_id is different from the
            current state of this token
        """

        self.ensure_state_is_in([state_id])

    def ensure_state_is_in(self, valid_state_ids):
        """
        a barrier method to ensure that the token state is
        in a list of valid_states

        :param valid_state_ids: A list of allowed states
        :raises TokenStateError: If token state is not in
            the list of valid states
        """

        current_state_id = self.getFromTokenInfo('state')
        if not current_state_id in valid_state_ids:
            raise TokenStateError('Token %r must be in one of the following '
                                  'states for this action: %s, but current '
                                  'state is %s' %
                                  (self, ','.join(valid_state_ids),
                                   current_state_id))

    def change_state(self, state_id):
        """
        changes the state of this token

        :param state_id: The new state_id this token should have
        """

        self.addToTokenInfo('state', state_id)


class TokenClass(object):

    def __init__(self, token):
        self.type = ''
        self.token = token
        # the info is a generic container, to store token specific
        # processing info, which could be retrieved in the controllers
        self.info = {}
        self.hKeyRequired = False
        self.mode = ['auth', 'challenge']
        # these lists will be returned as result of the token check
        self.challenge_token = []
        self.pin_matching_token = []
        self.invalid_token = []
        self.valid_token = []
        self.related_challenges = []
        self.auth_info = {}
        self.transId = None
        self.matching_challenges = []
        self.supports_offline_mode = False

    def setType(self, typ):
        typ = u'' + typ
        self.type = typ
        self.token.setType(typ)

    def is_auth_only_token(self, user):
        """
        check if token is in the authenticate only mode
        this is required to optimize the number of requests

        :param user: the user / realm where the token policy is applied
        :return: boolean
        """
        if len(self.mode) == 1 and 'authenticate' in self.mode:
            return True

        if len(self.mode) == 1 and 'challenge' in self.mode:
            return False

        import linotp.lib.policy
        support_challenge_response = \
            linotp.lib.policy.get_auth_challenge_response(user, self.type)

        return not support_challenge_response

    def is_challenge_and_auth_token(self, user):
        """
        check if token supports both authentication methods:
          authenticate an challenge responser

        :param user: the user / realm where the token policy is applied
        :return: boolean
        """

        if 'authenticate' in self.mode and 'challenge' in self.mode:
            import linotp.lib.policy
            support_challenge_response = \
                linotp.lib.policy.get_auth_challenge_response(user, self.type)
            return support_challenge_response
        else:
            return False

    # #########################################################################

    # interface hooks for generation of helper parameters in admin/init

    @classmethod
    def get_helper_params_pre(cls, params):
        """
        hook method which gets called with the parameters given to admin/init
        and returns a dictionary which will be added to the helper_params.
        In contrast to get_helper_params_post this function will be called
        _before_ the user object gets created from the parameters

        :params params: the request parameters supplied to admin/init
        :returns: dictionary with additional helper params
        """

        return {}

    @classmethod
    def get_helper_params_post(cls, params, user):
        """
        hook method which gets called with the parameters given to admin/init
        and the user that possibly gets created from it.
        It returns a dictionary which will be added to the helper_params.
        In contrast to get_helper_params_pre this function will be called
        _after_ the user object gets created from the parameters

        :params params: the request parameters supplied to admin/init
        :params user: the user object created from the request parameters
                      (None if no user was specified in the request)
        :returns: dictionary with additional helper params
        """

        return {}

    # #########################################################################

    @classmethod
    def getClassType(cls):
        return None

    @classmethod
    def getClassPrefix(cls):
        return "UNK"

    def getRealms(self):

        if hasattr(self, 'realms'):
            return self.realms

        realms = []
        tokenrealms = self.token.getRealms()
        for realm in tokenrealms:
            realms.append(realm.name)

        self.realms = realms
        return self.realms

    def getType(self):
        return self.token.getType()

    def addToInfo(self, key, value):
        self.info[key] = value
        return self.info

    def setInfo(self, info):
        if type(info) not in (dict):
            raise Exception("Info setting: wron data type - msut be dict")
        self.info = info
        return self.info

    def getInfo(self):
        '''
        getInfo - return the status of the token rollout

        :return: return the status dict.
        :rtype: dict
        '''
        log.debug('[getInfo] %r' % (self.info))
        return self.info

    def checkOtp(self, anOtpVal1, counter, window, options=None):
        '''
        This checks the OTP value, AFTER the upper level did
        the checkPIN

        return:
            counter of the matching OTP value.
        '''
        return -1

    def getOtp(self, curtTime=""):
        '''
        The default token does not support getting the otp value
        will return something like::

            1, pin, otpval, combined

        a negative value is a failure.
        '''
        return (-2, 0, 0, 0)

    def get_multi_otp(self, count=0, epoch_start=0, epoch_end=0, curTime=None):
        '''
        This returns a dictionary of multiple future OTP values of a token.

        parameter
            count    - how many otp values should be returned
            epoch_start    - time based tokens: start when
            epoch_end      - time based tokens: stop when

        return
            True/False
            error text
            OTP dictionary
        '''
        return (False, "get_multi_otp not implemented for this tokentype", {})

    # new highlevel interface which covers the checkPin and checkOTP
    def authenticate(self, passw, user, options=None):
        '''
        This is the method that verifies single shot authentication like
        they are done with push button tokens.

        It is a high level interface to support as well other tokens, which
        do not have a pin and otp seperation - they could overwrite
        this method

        **remarks:** we have to call the global methods (check_pin,++) as they
        take the pin policies into account

        :param passw: the passw which could be pin+otp
        :type passw: string
        :param user: The authenticating user
        :type user: User object
        :param options: dictionary of additional request parameters
        :type options: (dict)

        :return: returns tuple true or false for the pin match, the otpcounter
                 (int) and the reply (dict) that will be added as additional
                 information in the JSON response of ``/validate/check``.
        '''

        pin_match = False
        otp_counter = -1
        reply = None

        (res, pin, otpval) = split_pin_otp(self, passw, user, options=options)
        if res != -1:
            pin_policies = linotp.lib.policy.get_pin_policies(user)
            if 1 in pin_policies:
                otp_counter = check_otp(self, otpval, options=options)
                if otp_counter >= 0:
                    pin_match = check_pin(
                        self, pin, user=user, options=options)
                    if not pin_match:
                        otp_counter = -1
            else:
                pin_match = check_pin(self, pin, user=user, options=options)
                if pin_match is True:
                    otp_counter = check_otp(self, otpval, options=options)

        # for special token that have no otp like passwordtoken
        if not self.auth_info and pin_match is True and otp_counter == 0:
            self.auth_info = {'auth_info': [('pin_length', len(passw))]}

        return (pin_match, otp_counter, reply)

    # challenge interfaces starts here
    def is_challenge_request(self, passw, user, options=None):
        '''
        This method checks, if this is a request, that triggers a challenge.

        The default behaviour to trigger a challenge is,
        if the ``passw`` parameter only contains the correct token pin *and*
        the request contains a ``data`` or a ``challenge`` key i.e. if the
        ``options`` parameter contains a key ``data`` or ``challenge``.

        Each token type can decide on its own under which condition a challenge
        is triggered by overwriting this method.

        **please note**: in case of pin policy == 2 (no pin is required)
        the ``check_pin`` would always return true! Thus each request
        containing a ``data`` or ``challenge`` would trigger a challenge!

        :param passw: password, which might be pin or pin+otp
        :type passw: string
        :param user: The user from the authentication request
        :type user: User object
        :param options: dictionary of additional request parameters
        :type options: dict

        :return: true or false
        '''

        request_is_valid = False

        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            if "data" in options or "challenge" in options:
                request_is_valid = True

        return request_is_valid

    def is_challenge_response(self, passw, user, options=None,
                              challenges=None):
        '''
        This method checks, if this is a request, that is the response to
        a previously sent challenge.

        The default behaviour to check if this is the response to a
        previous challenge is simply by checking if the request contains
        a parameter ``state`` or ``transactionid`` i.e. checking if the
        ``options`` parameter contains a key ``state`` or ``transactionid``.

        This method does not try to verify the response itself!
        It only determines, if this is a response for a challenge or not.

        :param passw: password, which might be pin or pin+otp
        :type passw: string
        :param user: the requesting user
        :type user: User object
        :param options: dictionary of additional request parameters
        :type options: (dict)
        :param challenges: A list of challenges for this token. These
                           challenges may be used, to identify if this request
                           is a response for a challenge.

        :return: true or false
        '''

        challenge_response = False
        if "state" in options or "transactionid" in options:
            challenge_response = True

        # we leave out the checkOtp, which is done later
        # either in checkResponse4Challenge
        # or in the check pin+otp

        return challenge_response

    def get_challenge_validity(self):
        '''
        This method returns the token specific challenge validity

        :return: int - validity in seconds
        '''

        validity = 120

        try:
            validity = int(getFromConfig('DefaultChallengeValidityTime', 120))

            # handle the token specific validity
            typ = self.getType()
            lookup_for = typ.capitalize() + 'ChallengeValidityTime'
            validity = int(getFromConfig(lookup_for, validity))

            # instance specific timeout
            validity = int(self.getFromTokenInfo('challenge_validity_time',
                                                 validity))

        except ValueError:
            validity = 120

        return validity

    def is_challenge_valid(self, challenge=None):
        '''
        This method verifies if the given challenge is still valid.

        The default implementation checks, if the challenge start is in the
        default validity time window.

        **Please note**: This method does not check the response for the
        challenge itself. This is done by the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.checkResponse4Challenge`.
        E.g. this very method ``is_challenge_valid`` is used by the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.challenge_janitor`
        to clean up old challenges.

        :param challenge: The challenge to be checked
        :type challenge: challenge object
        :return: true or false
        '''

        validity = self.get_challenge_validity()
        ret = False

        if challenge is not None:
            c_start_time = challenge.get('timestamp')
            c_now = datetime.datetime.now()
            if c_now < c_start_time + datetime.timedelta(seconds=validity):
                ret = True

        return ret

    def initChallenge(self, transactionid, challenges=None, options=None):
        """
        This method initializes the challenge.

        This is a hook that is called before the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.createChallenge`, which
        will only be called if this method returns success==true.

        Thus this method can be used, to verify if there is an outstanding
        challenge or if a new challenge needs to be created.
        E.g. this hook can be used, to implement a blocking mechanism to
        allow the creation of a new challenge only after a certain timeout.
        If there is an already outstanding challenge the return value can refer
        to this. (s. ticket #2986)

        :param transactionid: the id of the new challenge
        :type transactionid: string
        :param options: the request parameters
        :type options: dict
        :param challenges: a list of all valid challenges for this token.
        :type challenges: list

        :return: tuple of ( success, transid, message, additional attributes )

        The ``transid`` (the best transaction id for this request context),
        ``message``, and additional ``attributes`` (dictionar) are displayed
        as results in the JSON response of the ``/validate/check`` request.

        Only in case of ``success`` == true the next method ``createChallenge``
        will be called.
        """
        return (True, transactionid, 'challenge init ok', {})

    def checkResponse4Challenge(self, user, passw, options=None,
                                challenges=None):
        '''
        This method verifies if the given ``passw`` matches any existing
        ``challenge`` of the token.

        It then returns the new otp_counter of the token and the
        list of the matching challenges.

        In case of success the otp_counter needs to be > 0.
        The matching_challenges is passed to the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.challenge_janitor`
        to clean up challenges.

        :param user: the requesting user
        :type user: User object
        :param passw: the password (pin+otp)
        :type passw: string
        :param options:  additional arguments from the request, which could
                         be token specific
        :type options: dict
        :param challenges: A sorted list of valid challenges for this token.
        :type challenges: list
        :return: tuple of (otpcounter and the list of matching challenges)

        '''
        otp_counter = -1
        transid = None
        matching = None
        matching_challenges = []

        if 'transactionid' in options or 'state' in options:
            # fetch the transactionid
            transid = options.get('transactionid', None)
            if transid is None:
                transid = options.get('state', None)

        # check if the transactionid is in the list of challenges
        if transid is not None:
            for challenge in challenges:
                if Challenges.is_same_transaction(challenge, transid):
                    matching = challenge
                    break
            if matching is not None:
                otp_counter = check_otp(self, passw, options=options)
                if otp_counter >= 0:
                    matching_challenges.append(matching)

        return (otp_counter, matching_challenges)

    def challenge_janitor(self, matching_challenges, challenges):
        '''
        This is the default janitor for the challenges of a token.

        The idea is to delete all challenges, which have an id lower than
        the matching one. Other janitors could be implemented on a token base
        and overwrite this behaviour.

        **Remarks**: In later versions this will be the place to hook a
        dynamically loaded default token specific janitor.

        :param matching_challenges: the last matching challenge
        :type matching_challenges: list
        :param challenges: all current challenges
        :type challenges: list

        :return: list of all challenges, which should be deleted
        '''

        to_be_closed = []
        if matching_challenges:
            match_id = 0
            for match in matching_challenges:
                match_id = max([match_id, int(match.get('id'))])

            # other, minor challenge will be closes as well
            for ch in challenges:
                if int(ch.get('id')) < match_id:
                    to_be_closed.append(ch)

        return to_be_closed

    def createChallenge(self, transactionid, options=None):
        """
        This method creates a challenge, which is submitted to the user.
        The submitted challenge will be preserved in the challenge
        database.

        This method is called *after* the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.initChallenge`.

        :param transactionid: the id of this challenge
        :param options: the request context parameters / data
        :type options: dict
        :return: tuple of (bool, message, data, attributes)

        The return tuple builds up like this:

        ``bool`` if submit was successfull;
        ``message`` which is displayed in the JSON response;
        ``data`` is preserved in the challenge;
        additional ``attributes``, which are displayed in the JSON response.
        """

        message = 'Otp: '
        data = {'serial': self.getSerial()}
        attributes = None
        return (True, message, data, attributes)

    def check_token(self, passw, user, options=None, challenges=None):
        """
        validate a token against the provided pass

        :raises: "challenge not found",
                 if a state is given and no challenge is found for this
                 challenge id

        :param passw: the password, which could either be a pin, a pin+otp
                       or otp
        :param user: the user which the token belongs to
        :param options: dict with additional request parameters
        :param challenges:

        :return: tuple of otpcounter and potential reply
        """
        log.debug("entering function checkToken(%r)" % self)
        res = -1
        if options is None:
            options = {}

        # fallback in case of check_s, which does not provide a user
        # but as for further prcessing a dummy user with only the realm defined
        # is required for the policy evaluation
        if user is None:
            user = self.get_token_realm_user()

        # standard authentication token
        if self.is_auth_only_token(user):
            (res, reply) = self.check_authenticate(user, passw,
                                                   options=options)
            return (res, reply)

        # only challenge response token authentication
        if not self.is_challenge_and_auth_token(user):

            # first check are there outstanding challenges
            if self.is_challenge_response(passw, user,
                                          options=options,
                                          challenges=challenges):

                (res, reply) = self.check_challenge_response(challenges,
                                                             user, passw,
                                                             options=options)
                return (res, reply)

            res = self.is_challenge_request(passw, user, options=options)
            if res:
                self.challenge_token.append(self)
            else:
                self.invalid_token.append(self)

            return (False, None)

        # else: tokens, which support both: challenge response
        # and standard authentication

        # first check are there outstanding challenges
        if self.is_challenge_response(passw, user,
                                      options=options,
                                      challenges=challenges):

            (res, reply) = self.check_challenge_response(challenges,
                                                         user, passw,
                                                         options=options)
            return (res, reply)

        # if all okay, we can return here
        (res, reply) = self.check_authenticate(user, passw, options=options)
        if res >= 0:
            return (res, reply)

        # any challenge trigger should return false
        res = self.is_challenge_request(passw, user, options=options)
        if res:
            self.challenge_token.append(self)
        else:
            self.invalid_token.append(self)

        return (False, None)

    def check_challenge_response(self, challenges, user, passw, options=None):
        """
        This function checks, if the given response (passw) matches
        any of the open challenges

        to prevent the token author to deal with the database layer, the
        token.checkResponse4Challenge will recieve only the dictionary of the
        challenge data

        :param challenges: the list of database challenges
        :param user: the requesting use
        :param passw: the to password of the request, which must be pin+otp
        :param options: the addtional request parameters
        :return: tuple of otpcount (as result of an internal token.checkOtp)
                 and additional optional reply
        """
        # challenge reply will stay None as we are in the challenge response
        # mode
        reply = None
        if options is None:
            options = {}

        otp = passw
        self.transId = options.get('transactionid', options.get('state', None))

        # only check those challenges, which currently have not been verified
        check_challenges = []
        for ch in challenges:
            if Challenges.verify_checksum(ch) and ch.is_open():
                check_challenges.append(ch)

        (otpcount, matching_challenges) = self.checkResponse4Challenge(
            user, otp, options=options, challenges=check_challenges)

        if otpcount >= 0:
            self.matching_challenges = matching_challenges
            self.valid_token.append(self)
            if len(self.invalid_token) > 0:
                del self.invalid_token[0]
        else:
            self.invalid_token.append(self)

        return (otpcount, reply)

    def get_token_realm_user(self):

        user = None
        realms = linotp.lib.token.getTokenRealms(self.getSerial())
        if len(realms) == 1:
            user = linotp.lib.user.User(login='', realm=realms[0])
        elif len(realms) == 0:
            realm = linotp.lib.token.getDefaultRealm()
            user = linotp.lib.user.User(login='', realm=realm)
            log.info('No token realm found - using default realm.')
        else:
            msg = ('Multiple realms for token found. But one dedicated '
                   'realm is required for further processing.')
            log.error(msg)
            raise Exception(msg)

        return user

    def check_authenticate(self, user, passw, options=None):
        '''
        simple authentication with pin+otp

        :param passw: the password, which should be checked
        :param options: dict with additional request parameters

        :return: tuple of matching otpcounter and a potential reply
        '''

        pin_match, otp_count, reply = self.authenticate(passw, user,
                                                        options=options)
        if otp_count >= 0:
            self.valid_token.append(self)
        elif pin_match is True:
            self.pin_matching_token.append(self)
        else:
            self.invalid_token.append(self)

        return (otp_count, reply)

    def check_standard(self, passw, user, options=None):
        """
        do a standard verification, as we are not in a challengeResponse mode

        the upper interfaces expect in the success the otp counter or at
        least 0 if we have a success. A -1 identifies an error

        :param passw: the password, which should be checked
        :param options: dict with additional request parameters

        :return: tuple of matching otpcounter and a potential reply
        """

        otp_count = -1
        pin_match = False
        reply = None

        # fallback in case of check_s, which does not provide a user
        # but as for further prcessing a dummy user with only the realm defined
        # is required for the policy evaluation
        if user is None:
            import linotp.lib.token
            realms = linotp.lib.token.getTokenRealms(self.getSerial())
            if len(realms) == 1:
                user = linotp.lib.user.User(login='', realm=realms[0])
            elif len(realms) == 0:
                realm = linotp.lib.token.getDefaultRealm()
                user = linotp.lib.user.User(login='', realm=realm)
                log.info('No token realm found - using default realm.')
            else:
                msg = ('Multiple realms for token found. But one dedicated '
                       'realm is required for further processing.')
                log.error(msg)
                raise Exception(msg)
        import linotp.lib.policy
        support_challenge_response = \
            linotp.lib.policy.get_auth_challenge_response(user, self.getType())

        if len(self.mode) == 1 and self.mode[0] == "challenge":
            # the support_challenge_response is overruled, if the token
            # supports only challenge processing
            support_challenge_response = True

        try:
            # call the token authentication
            (pin_match, otp_count, reply) = self.authenticate(passw, user,
                                                              options=options)
        except Exception as exx:
            if (support_challenge_response is True and
                    self.is_challenge_request(passw, user, options=options)):
                log.info("Retry on base of a challenge request:")
                pin_match = False
                otp_count = -1
            else:
                log.exception("%r" % exx)
                raise Exception(exx)

        if otp_count < 0 or pin_match is False:
            if (support_challenge_response is True and
                    self.isActive() and
                    self.is_challenge_request(passw, user, options=options)):
                # we are in createChallenge mode
                # fix for #12413:
                # - moved the create_challenge call to the checkTokenList!
                # after all tokens are processed and only one is challengeing
                # (_res, reply) = create_challenge(self.token, options=options)
                self.challenge_token.append(self)

        if len(self.challenge_token) == 0:
            if otp_count >= 0:
                self.valid_token.append(self)
            elif pin_match is True:
                self.pin_matching_token.append(self)
            else:
                self.invalid_token.append(self)

        return (otp_count, reply)

    def get_related_challenges(self):
        """
        :return: list of related challenges
        """
        return self.related_challenges

    def get_verification_result(self):
        """
        return the internal result representation of the token verification
        which are a set of list, which stand for the challenge, pinMatching
        or invalid or valid token list

        - the lists are returned as they easily could be joined into the final
          token list, independent of they are empty or contain a token obj

        :return: tuple of token lists
        """
        return (self.challenge_token, self.pin_matching_token,
                self.invalid_token, self.valid_token)

    def flush(self):
        self.token.storeToken()
        Session.flush()
        Session.commit()
        return

    def update(self, param, reset_failcount=True):

        tdesc = getParam(param, "description", optional)
        if tdesc is not None:
            self.token.setDescription(tdesc)

        # key_size as parameter overrules a prevoiusly set
        # value e.g. in hashlib in the upper classes
        key_size = getParam(param, "keysize", optional)
        if key_size is None:
            key_size = 20

        ##
        # process the otpkey:
        #   if otpkey given - take this
        #   if not given
        #       if genkey == 1 : create one
        #   if required and otpkey is None:
        #      raise param Exception, that we require an otpkey
        ##
        otpKey = getParam(param, "otpkey", optional)
        genkey = int(getParam(param, "genkey", optional) or 0)

        if genkey not in [0, 1]:
            raise Exception("TokenClass supports only genkey in "
                            "range [0,1] : %r" % genkey)

        if genkey == 1 and otpKey is not None:
            raise ParameterError('[ParameterError] You may either specify'
                                 'genkey or otpkey, but not both!', id=344)

        if otpKey is not None:
            self.setOtpKey(otpKey, reset_failcount=reset_failcount)
        else:
            if genkey == 1:
                otpKey = self._genOtpKey_()

        # otpKey still None?? - raise the exception
        if otpKey is None:
            if self.hKeyRequired is True:
                otpKey = getParam(param, "otpkey", required)

        if otpKey is not None:
            self.addToInfo('otpkey', otpKey)
            self.setOtpKey(otpKey)

        pin = getParam(param, "pin", optional)
        if pin is not None:
            self.setPin(pin, param=param)

        otplen = param.get('otplen', None)
        if otplen:
            self.setOtpLen(otplen)

        self.resetTokenInfo()

        return

    def resetTokenInfo(self):
        """
        TODO: to be implemented or to be removed!
        """
        return

    def _genOtpKey_(self, otpkeylen=None):
        '''
        private method, to create an otpkey

        :param otpkeylen: optional or 20
        :return: token seed / secret
        '''
        if otpkeylen is None:
            if hasattr(self, 'otpkeylen'):
                otpkeylen = getattr(self, 'otpkeylen')
            else:
                otpkeylen = 20
        return generate_otpkey(otpkeylen)

    def setDescription(self, description):
        """
        set the token description
        :param description: set the token description
        """
        self.token.setDescription(u'' + description)
        return

    def setDefaults(self):
        # set the defaults

        self.token.LinOtpOtpLen = int(getFromConfig("DefaultOtpLen") or 6)
        self.token.LinOtpCountWindow = int(getFromConfig("DefaultCountWindow")
                                           or 10)
        self.token.LinOtpMaxFail = int(getFromConfig("DefaultMaxFailCount")
                                       or 10)
        self.token.LinOtpSyncWindow = int(getFromConfig("DefaultSyncWindow")
                                          or 1000)

        self.token.LinOtpTokenType = u'' + self.type
        return

    def setUser(self, user, report):
        '''
        :param user: a User() object, consisting of loginname and realm
        :param report: tbdf.
        '''
        (uuserid, uidResolver, uidResolverClass) = getUserResolverId(user,
                                                                     report)
        self.token.LinOtpIdResolver = uidResolver
        self.token.LinOtpIdResClass = uidResolverClass
        self.token.LinOtpUserid = uuserid

    def getUser(self):
        """
        get the user info of the token

        :return: tuple of user id, user resolver and resolver class
        """
        uidResolver = self.token.LinOtpIdResolver or ''
        uidResolverClass = self.token.LinOtpIdResClass or ''

        # we adjust the token-resolver-class-info to match
        # to the available un-ee resolvers, which makes the live
        # alot easier
        if 'useridresolveree.' in uidResolverClass:
            uidResolverClass = uidResolverClass.replace('useridresolveree.',
                                                        'useridresolver.')
        uuserid = self.token.LinOtpUserid or ''
        return (uuserid, uidResolver, uidResolverClass)

    def setUid(self, uid, uidResolver, uidResClass):
        '''
        sets the UID values in the database
        '''
        self.token.LinOtpIdResolver = uidResolver
        self.token.LinOtpIdResClass = uidResClass
        self.token.LinOtpUserid = uid
        return

    def reset(self):
        """
        reset the token failcount value
        """
        self.token.LinOtpFailCount = 0

    def addToSession(self, Session):
        Session.add(self.token)

    def deleteToken(self):
        self.token.deleteToken()

    def storeToken(self):
        self.token.storeToken()

    def resync(self, otp1, otp2, options=None):
        pass

    def getOtpCountWindow(self):
        return self.token.LinOtpCountWindow

    def getOtpCount(self):
        return self.token.LinOtpCount

    def isActive(self):
        return self.token.LinOtpIsactive

    def getFailCount(self):
        return self.token.LinOtpFailCount

    def setFailCount(self, failCount):
        self.token.LinOtpFailCount = failCount

    def getMaxFailCount(self):
        return self.token.LinOtpMaxFail

    def getUserId(self):
        return self.token.LinOtpUserid

    def setRealms(self, realms):
        self.token.setRealms(realms)

    def getSerial(self):
        return self.token.getSerial()

    def setSoPin(self, soPin):
        """
        set the soPin of the token
            the soPin is encrypted and the encrypte value is stored in the
            Token model

        :param soPin: the special so pin
        """
        iv, enc_soPin = SecretObj.encrypt(soPin, hsm=context.get('hsm'))
        self.token.setSoPin(enc_soPin, iv)

    def setUserPin(self, userPin):
        """
        set the userPin of the token
            the userPin is encrypted and the encrypte value is stored in the
            Token model

        :param userPin: the user pin
        """

        log.debug('setUserPin()')
        iv, enc_user_pin = SecretObj.encrypt(userPin, hsm=context['hsm'])
        self.token.setUserPin(enc_user_pin, iv)

    def setOtpKey(self, otpKey, reset_failcount=True):
        """
        set the token seed / secret
            the seed / secret is encrypted and the encrypte value is
            stored in the Token model

        :param otpKey: the token seed / secret
        :param reset_failcount: boolean, if the failcounter should be reseted
        """
        iv, enc_otp_key = SecretObj.encrypt(otpKey, hsm=context['hsm'])
        self.token.set_encrypted_seed(enc_otp_key, iv,
                                      reset_failcount=reset_failcount)

    def setOtpLen(self, otplen):
        self.token.LinOtpOtpLen = int(otplen)

    def getOtpLen(self):
        return self.token.LinOtpOtpLen

    def setOtpCount(self, otpCount):
        self.token.LinOtpCount = int(otpCount)

    def setPin(self, pin, param=None):
        '''
        set the PIN. The optional parameter "param" can hold the information,
        if the PIN is encrypted or hashed.

        :param pin: the pin value
        :param param: the additional request parameters, which could contain
                      the 'encryptpin' value, that triggers, that the token
                      secret are stored in an encrypted form
        :return: - nothing -
        '''
        if param is None:
            param = {}

        hsm = context['hsm']
        storeHashed = True
        enc = param.get("encryptpin", None)
        if enc is not None and "true" == enc.lower():
            storeHashed = False

        if storeHashed is True:
            iv, hashed_pin = SecretObj.hash_pin(pin, hsm=hsm)
            self.token.set_hashed_pin(hashed_pin, iv)
        else:
            enc_pin = SecretObj.encrypt_pin(pin, hsm=hsm)
            iv = enc_pin.split(':')[0]
            self.token.set_encrypted_pin(enc_pin, binascii.unhexlify(iv))

    def getPin(self):
        """
        :return: the value of the pin- if it is stored encrypted
        """
        pin = ''
        hsm = context['hsm']
        if self.token.isPinEncrypted():
            _iv, enc_pin = self.token.get_encrypted_pin()
            pin = SecretObj.decrypt_pin(enc_pin, hsm=hsm)
        return pin

    def _get_secret_object(self):
        """
        encapsulate the returning of the secret object

        the returning of the SecretObj to allow delayed access to the token
        seed eg. only when hmac is calculated, the secret will be decrypted

        :return: SecretObject, containing the token seed
        """
        key, iv = self.token.get_encrypted_seed()
        secObj = SecretObj(key, iv, hsm=context['hsm'])
        return secObj

    def enable(self, enable):
        self.token.LinOtpIsactive = enable

    def setMaxFail(self, maxFail):
        self.token.LinOtpMaxFail = maxFail

    def setHashLib(self, hashlib):
        self.addToTokenInfo("hashlib", hashlib)

    def incOtpFailCounter(self):
        log.debug('incOtpFailCounter')

        self.token.LinOtpFailCount = self.token.LinOtpFailCount + 1

        try:
            self.token.storeToken()
        except:
            log.exception('update failed')
            raise TokenAdminError("Token Fail Counter update failed", id=1106)

        return self.token.LinOtpFailCount

    # TODO: - this is only HMAC??
    def setCounterWindow(self, countWindow):
        self.token.LinOtpCountWindow = int(countWindow)

    def getCounterWindow(self):
        return self.token.LinOtpCountWindow

    def setSyncWindow(self, syncWindow):
        self.token.LinOtpSyncWindow = int(syncWindow)

    def getSyncWindow(self):
        return self.token.LinOtpSyncWindow

    # hashlib algorithms:
    # http://www.doughellmann.com/PyMOTW/hashlib/index.html#module-hashlib

    def getHashlib(self, hLibStr):

        if hLibStr is None:
            return hashlib.sha1

        hashlibStr = hLibStr.lower()

        if hashlibStr == "md5":
            return hashlib.md5
        elif hashlibStr == "sha1":
            return hashlib.sha1
        elif hashlibStr == "sha224":
            return hashlib.sha224
        elif hashlibStr == "sha256":
            return hashlib.sha256
        elif hashlibStr == "sha384":
            return hashlib.sha384
        elif hashlibStr == "sha512":
            return hashlib.sha512
        else:
            return hashlib.sha1

    def getTokenInfo(self):
        info = {}

        tokeninfo = self.token.getInfo()
        if tokeninfo is not None and len(tokeninfo.strip()) > 0:
            try:
                info = json.loads(tokeninfo)
            except Exception as e:
                log.exception('getTokenInfo %r' % (e))

        return info

    def setTokenInfo(self, info):

        if info is not None:
            tokeninfo = u'' + json.dumps(info, indent=0)
            self.token.setInfo(tokeninfo)

    def addToTokenInfo(self, key, value):
        info = {}
        tokeninfo = self.token.getInfo()

        if tokeninfo:
            info = json.loads(tokeninfo)

        info[key] = value

        self.setTokenInfo(info)

    def getFromTokenInfo(self, key, default=None):
        ret = default

        info = self.getTokenInfo()

        if key in info:
            ret = info.get(key)
        return ret

    def removeFromTokenInfo(self, key):
        info = self.getTokenInfo()
        if key in info:
            del info[key]
            self.setTokenInfo(info)

    # FIXME: we could store the
    #   count_auth_success_max
    #   count_auth_success
    # and
    #   count_auth_max
    #   count_auth
    # in dedicated columns!
    def set_count_auth_success_max(self, count):
        '''
        Sets the counter for the maximum allowed successful logins
        '''
        self.addToTokenInfo("count_auth_success_max", int(count))

    def set_count_auth_success(self, count):
        '''
        Sets the counter for the occurred successful logins
        '''
        self.addToTokenInfo("count_auth_success", int(count))

    def set_count_auth_max(self, count):
        '''
        Sets the counter for the maximum allowed login attemps
        '''
        self.addToTokenInfo("count_auth_max", int(count))

    def set_count_auth(self, count):
        '''
        Sets the counter for the occurred login attepms
        '''
        self.addToTokenInfo("count_auth", int(count))

    def get_count_auth_success_max(self):
        ret = 0
        try:
            ret = int(self.getFromTokenInfo("count_auth_success_max"))
        except:
            pass
        return ret

    def get_count_auth_success(self):
        ret = 0
        try:
            ret = int(self.getFromTokenInfo("count_auth_success"))
        except:
            pass
        return ret

    def get_count_auth_max(self):
        ret = 0
        try:
            ret = int(self.getFromTokenInfo("count_auth_max"))
        except:
            pass
        return ret

    def get_count_auth(self):
        ret = 0
        try:
            ret = int(self.getFromTokenInfo("count_auth"))
        except:
            pass
        return ret

    def get_validity_period_end(self):
        '''
        returns the end of validity period (if set)
        '''
        ret = ""
        try:
            ret = self.getFromTokenInfo("validity_period_end")
        except:
            pass
        return ret

    def set_validity_period_end(self, end_date):
        '''
        sets the end date of the validity period for a token
        '''
        # upper layer will catch. we just try to verify the date format
        datetime.datetime.strptime(end_date, "%d/%m/%y %H:%M")

        self.addToTokenInfo("validity_period_end", end_date)

    def get_validity_period_start(self):
        '''
        returns the start of validity period (if set)
        '''
        ret = ""
        try:
            ret = self.getFromTokenInfo("validity_period_start")
        except:
            pass
        return ret

    def set_validity_period_start(self, start_date):
        '''
        sets the start date of the validity period for a token
        '''
        #  upper layer will catch. we just try to verify the date format
        datetime.datetime.strptime(start_date, "%d/%m/%y %H:%M")
        self.addToTokenInfo("validity_period_start", start_date)

    def inc_count_auth_success(self):
        count = self.get_count_auth_success()
        count += 1
        self.set_count_auth_success(count)
        return count

    def inc_count_auth(self):
        count = self.get_count_auth()
        count += 1
        self.set_count_auth(count)
        return count

    def check_auth_counter(self):
        '''
        This function checks the count_auth and the count_auth_success
        '''
        if 0 != self.get_count_auth_max():
            if self.get_count_auth() >= self.get_count_auth_max():
                return False

        if 0 != self.get_count_auth_success_max():
            if (self.get_count_auth_success() >=
                    self.get_count_auth_success_max()):
                return False

        return True

    def check_validity_period(self):
        '''
        This checks if the datetime.datetime.now() is within the
        validity period of the token.

        Returns either True/False
        '''
        start = self.get_validity_period_start()
        end = self.get_validity_period_end()

        check_start = False
        check_end = False
        try:
            dt_start = datetime.datetime.strptime(start, "%d/%m/%y %H:%M")
            check_start = True
        except:
            pass

        try:
            dt_end = datetime.datetime.strptime(end, "%d/%m/%y %H:%M")
            check_end = True
        except:
            pass

        if check_end:
            if dt_end < datetime.datetime.now():
                return False

        if check_start:
            if dt_start > datetime.datetime.now():
                return False

        return True

    def incOtpCounter(self, counter=None, reset=True):
        '''
        method
            incOtpCounter(aToken, counter)

        parameters:
            token - a token object
            counter - the new counter
            reset - optional -

        exception:
            in case of an transaction fail an exception is thrown

        side effects:
            default of reset will reset the failCounter

        '''
        log.debug('incOtpCounter')

        resetCounter = False

        if counter is None:
            counter = self.token.LinOtpCount

        log.debug("[incOtpCounter] got counter %s, %s" %
                  (self.token.LinOtpCount, counter))
        self.token.LinOtpCount = counter + 1

        if reset is True:
            if getFromConfig("DefaultResetFailCount") == "True":
                resetCounter = True

        if resetCounter is True:
            if (self.token.LinOtpFailCount < self.token.LinOtpMaxFail and
                    self.token.LinOtpIsactive is True):
                self.token.LinOtpFailCount = 0

        try:
            self.token.storeToken()

        except Exception as ex:
            log.exception("Token Counter update failed: %r" % (ex))
            raise TokenAdminError("Token Counter update failed: %r" % (ex),
                                  id=1106)

        log.debug("[incOtpCounter] now got counter %s, %s" %
                  (self.token.LinOtpCount, counter))
        return self.token.LinOtpCount

    def check_otp_exist(self, otp, window=None, user=None, autoassign=False):
        '''
        checks if the given OTP value is/are values of this very token.
        This is used to autoassign and to determine the serial number of
        a token.
        '''
        return -1

    def splitPinPass(self, passw):
        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError:
            otplen = 6

        auth_info = []
        if getFromConfig("PrependPin") == "True":
            pin = passw[0:-otplen]
            otpval = passw[-otplen:]
            auth_info.append(('pin_length', len(pin)))
            auth_info.append(('otp_length', len(otpval)))
        else:
            pin = passw[otplen:]
            otpval = passw[0:otplen]
            auth_info.append(('otp_length', len(otpval)))
            auth_info.append(('pin_length', len(pin)))

        self.auth_info['auth_info'] = auth_info

        return pin, otpval

    def checkPin(self, pin, options=None):
        '''
        checkPin - test is the pin is matching

        :param pin:      the pin
        :param options:  additional optional parameters, which could
                         be token specific
        :return: boolean

        '''
        res = False
        log.debug("[checkPin] entering checkPin function")

        hsm = context['hsm']
        if self.token.isPinEncrypted():
            # for comparison we encrypt the pin and do the comparison
            iv, encrypted_token_pin = self.token.get_encrypted_pin()
            encrypted_pin = SecretObj.encrypt_pin(pin, iv=iv, hsm=hsm)
            if encrypted_token_pin == encrypted_pin:
                res = True
        else:
            # for hased pins we redo the hash and compare the hashes
            iv, hashed_token_pin = self.token.get_hashed_pin()
            iv, hashed_pin = SecretObj.hash_pin(pin or '', iv, hsm=hsm)
            if hashed_pin == hashed_token_pin:
                res = True

            # special case of empty pin, where pin has never been set
            # especialy in case of lost token with the pw token
            if len(hashed_token_pin) == 0 and len(pin) == 0:
                res = True

        log.debug("[checkPin] result %r" % res)
        return res

    @staticmethod
    def copy_pin(src, target):
        import linotp.model
        linotp.model.Token.copy_pin(src.token, target.token)

    def statusValidationFail(self):
        """
        callback to enable a status change, when authentication failed
        """
        return

    def statusValidationSuccess(self):
        """
        callback to enable a status change, on authentication success
        """
        return

    def __repr__(self):
        '''
        return the token state as text

        :return: token state as string representation
        :rtype:  string
        '''
        ldict = {}
        for attr in self.__dict__:
            key = "%r" % attr
            val = "%r" % getattr(self, attr)
            ldict[key] = val
        res = "<%r %r>" % (self.__class__, ldict)
        return res

    def get_vars(self, save=False):
        '''
        return the token state as dicts
        :return: token as dict
        '''
        ldict = {}
        for attr in self.__dict__:
            key = attr
            if key == 'context':
                continue
            val = getattr(self, attr)
            if type(val) in [list, dict, str, unicode, int, float, bool]:
                ldict[key] = val
            elif type(val).__name__.startswith('Token'):
                ldict[key] = val.get_vars(save=save)
            else:
                ldict[key] = "%r" % val
        return ldict

    def getAuthDetail(self):

        return self.auth_info

    def getOfflineInfo(self):
        return {}

    def getInitDetail(self, params, user=None):
        '''
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        '''

        _ = context['translate']

        response_detail = {}

        info = self.getInfo()
        response_detail.update(info)
        response_detail['serial'] = self.getSerial()

        otpkey = None
        if 'otpkey' in info:
            otpkey = info.get('otpkey')

        if otpkey is not None:
            response_detail["otpkey"] = {"order": '1',
                                         "description": _("OTP seed"),
                                         "value":  "seed://%s" % otpkey,
                                         "img":  create_img(otpkey, width=200),
                                         }

        return response_detail

    def getQRImageData(self, response_detail):
        '''
        '''
        url = None
        hparam = {}

        if response_detail is not None:
            if 'googleurl' in response_detail:
                url = response_detail.get('googleurl')
                hparam['alt'] = url

        return url, hparam


### OcraTokenClass #####################################


class OcraTokenClass(TokenClass):
    """
    OcraTokenClass  implement an ocra compliant token

    used from Config
        OcraMaxChallenges:    number of open challenges per token if None: 3
        OcraChallengeTimeout: timeout definition like 1D, 2H or 3M if None: 1M
        OcraDefaultSuite:     if none :'OCRA-1:HOTP-SHA256-8:C-QN08'
        QrOcraDefaultSuite:   if none :'OCRA-1:HOTP-SHA256-8:C-QA64'


    algorithm Ocra Token Rollout: two phases of rollout::

        1. https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            sharedsecret=1&
            user=BENUTZERNAME&
            session=SESSIONKEY

            =>> "serial" : SERIENNUMMER, "sharedsecret" : DATAOBJECT,
                                  "app_import" : IMPORTURL
            - genSharedSecret - vom HSM oder urandom ?
            - app_import : + linotp://
                        + ocrasuite ->> default aus dem config:
                                                    (DefaultOcraSuite)
                        + sharedsecret (Länge wie ???)
                        + seriennummer
            - seriennummer: uuid
            - token wird angelegt ist aber nicht aktiv!!! (counter == 0)


        2. https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            activationcode=AKTIVIERUNGSCODE&
            user=BENUTZERNAME&
            message=MESSAGE&
            session=SESSIONKEY

            =>> "serial" : SERIENNUMMER, "nonce" : DATAOBJECT,
                "transactionid" : "TRANSAKTIONSID, "app_import" : IMPORTURL

            - nonce - von HSM oder random ?
            - pkcs5 - kdf2
            - es darf zur einer Zeit nur eine QR Token inaktiv
                   (== im Ausrollzustand) sein !!!!!
            der Token wird über den User gefunden
            - seed = pdkdf2(nonce + activcode + shared secret)
            - challenge generiern - von urandom oder HSM

        3. check_t
            - counter ist > nach der ersten Transaktion
            - if counter >= 1: delete sharedsecret löschen
    """

    @classmethod
    def get_helper_params_post(cls, param, user=None):

        helper_param = {}

        tok_type = "ocra"

        # take the keysize from the ocrasuite
        ocrasuite = param.get("ocrasuite", None)
        activationcode = param.get("activationcode", None)
        sharedsecret = param.get("sharedsecret", None)
        serial = param.get("serial", None)
        genkey = param.get("genkey", None)

        if activationcode is not None:
            # dont create a new key
            genkey = None
            serial = getRolloutToken4User(user=user, serial=serial,
                                          tok_type=tok_type)
            if serial is None:
                raise Exception('no token found for user: %r or serial: %r'
                                % (user, serial))
            helper_param['serial'] = serial
            helper_param['activationcode'] = \
                normalize_activation_code(activationcode)

        if ocrasuite is None:
            if sharedsecret is not None or activationcode is not None:
                ocrasuite = getFromConfig("QrOcraDefaultSuite",
                                          'OCRA-1:HOTP-SHA256-6:C-QA64')
            else:
                ocrasuite = getFromConfig("OcraDefaultSuite",
                                          'OCRA-1:HOTP-SHA256-8:C-QN08')
            helper_param['ocrasuite'] = ocrasuite

        if genkey is not None:
            if ocrasuite.find('-SHA256'):
                key_size = 32
            elif ocrasuite.find('-SHA512'):
                key_size = 64
            else:
                key_size = 20
            helper_param['key_size'] = key_size

        return helper_param

    @classmethod
    def getClassType(cls):
        '''
        getClassType - return the token type shortname

        :return: 'ocra'
        :rtype: string
        '''
        log.debug('[getClassType] ocra')
        return "ocra"

    @classmethod
    def getClassPrefix(cls):
        return "ocra"

    def __init__(self, aToken):
        '''
        getInfo - return the status of the token rollout

        :return: info of the ocra token state
        :rtype: dict
        '''
        log.debug('[__init__]')

        TokenClass.__init__(self, aToken)
        self.setType(u"ocra")
        self.transId = 0

        log.debug('[__init__]:')
        return

    def getInfo(self):
        '''
        getInfo - return the status of the token rollout

        :return: info of the ocra token state
        :rtype: dict
        '''
        log.debug('[getInfo] %r ' % (self.info))
        return self.info

    def update(self, params, reset_failcount=True):
        '''
        update: add further defintion for token from param in case of init
        '''
        log.debug('[update] %r: %r: ' % (params, reset_failcount))

        if 'ocrasuite' in params:
            self.ocraSuite = params.get('ocrasuite')
        else:
            activationcode = params.get('activationcode', None)
            sharedSecret = params.get('sharedsecret', None)

            if activationcode is None and sharedSecret is None:
                self.ocraSuite = self.getOcraSuiteSuite()
            else:
                self.ocraSuite = self.getQROcraSuiteSuite()

        if params.get('activationcode', None):
            # due to changes in the tokenclass parameter handling
            # we have to add for compatibility a genkey parameter
            if 'otpkey' not in params and 'genkey' not in params:
                log.warning('[OcraTokenClass:update] missing parameter genkey'
                            ' to complete the rollout 2!')
                params['genkey'] = 1

        TokenClass.update(self, params, reset_failcount=reset_failcount)

        self.addToTokenInfo('ocrasuite', self.ocraSuite)

        ocraSuite = OcraSuite(self.ocraSuite)
        otplen = ocraSuite.truncation
        self.setOtpLen(otplen)

        ocraPin = params.get('ocrapin', None)
        if ocraPin is not None:
            self.setUserPin(ocraPin)

        if 'otpkey' in params:
            self.setOtpKey(params.get('otpkey'))

        self._rollout_1(params)
        self._rollout_2(params)

        log.debug('[update]:')
        return

    def _rollout_1(self, params):
        '''
        do the rollout 1 step

        1. https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            sharedsecret=1&
            user=BENUTZERNAME&
            session=SESSIONKEY

            =>> "serial" : SERIENNUMMER, "sharedsecret" : DATAOBJECT,
                                         "app_import" : IMPORTURL
            - genSharedSecret - vom HSM oder urandom ?
            - app_import : + linotp://
                           + ocrasuite ->> default aus dem config:
                                                           (DefaultOcraSuite)
                           + sharedsecret (Länge wie ???)
                           + seriennummer
            - seriennummer: uuid ??
            - token wird angelegt ist aber nicht aktiv!!! (counter == 0)

        '''
        log.debug('[_rollout_1] %r ' % (params))

        sharedSecret = params.get('sharedsecret', None)
        if sharedSecret == '1':
            #  preserve the rollout state
            self.addToTokenInfo('rollout', '1')

            # preserve the current key as sharedSecret
            secObj = self._get_secret_object()
            key = secObj.getKey()
            encSharedSecret = encryptPin(key)
            self.addToTokenInfo('sharedSecret', encSharedSecret)

            info = {}
            uInfo = {}

            info['sharedsecret'] = key
            uInfo['sh'] = key

            info['ocrasuite'] = self.getOcraSuiteSuite()
            uInfo['os'] = self.getOcraSuiteSuite()

            info['serial'] = self.getSerial()
            uInfo['se'] = self.getSerial()

            info['app_import'] = 'lseqr://init?%s' % (urllib.urlencode(uInfo))
            del info['ocrasuite']
            self.info = info

            self.token.LinOtpIsactive = False

        log.debug('[_rollout_1]:')
        return

    def _rollout_2(self, params):
        '''
        2.

        https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            activationcode=AKTIVIERUNGSCODE&
            user=BENUTZERNAME&
            message=MESSAGE&
            session=SESSIONKEY

        =>> "serial" : SERIENNUMMER, "nonce" : DATAOBJECT,
            "transactionid" : "TRANSAKTIONSID, "app_import" : IMPORTURL

        - nonce - von HSM oder random ?
        - pkcs5 - kdf2
        - es darf zur einer Zeit nur eine QR Token inaktiv
                                        (== im Ausrollzustand) sein !!!!!
          der Token wird über den User gefunden
        - seed = pdkdf2(nonce + activcode + shared secret)
        - challenge generiern - von urandom oder HSM

        '''
        log.debug('[_rollout_2] %r ' % (params))

        activationcode = params.get('activationcode', None)
        if activationcode is not None:

            #  genkey might have created a new key, so we have to rely on
            encSharedSecret = self.getFromTokenInfo('sharedSecret', None)
            if encSharedSecret is None:
                raise Exception('missing shared secret of initialition'
                                ' for token %r' % (self.getSerial()))

            sharedSecret = decryptPin(encSharedSecret)

            #  we generate a nonce, which in the end is a challenge
            nonce = createNonce()
            self.addToTokenInfo('nonce', nonce)

            #  create a new key from the ocrasuite
            key_len = 20
            if self.ocraSuite.find('-SHA256'):
                key_len = 32
            elif self.ocraSuite.find('-SHA512'):
                key_len = 64

            newkey = kdf2(sharedSecret, nonce, activationcode, key_len)
            self.setOtpKey(binascii.hexlify(newkey))

            #  generate challenge, which is part of the app_import
            message = params.get('message', None)
            (transid, challenge, _ret, url) = self.challenge(message)

            #  generate response
            info = {}
            uInfo = {}
            info['serial'] = self.getSerial()
            uInfo['se'] = self.getSerial()
            info['nonce'] = nonce
            uInfo['no'] = nonce
            info['transactionid'] = transid
            uInfo['tr'] = transid
            info['challenge'] = challenge
            uInfo['ch'] = challenge
            if message is not None:
                uInfo['me'] = str(message.encode("utf-8"))

            ustr = urllib.urlencode({'u': str(url.encode("utf-8"))})
            uInfo['u'] = ustr[2:]
            info['url'] = str(url.encode("utf-8"))

            app_import = 'lseqr://nonce?%s' % (urllib.urlencode(uInfo))

            #  add a signature of the url
            signature = {'si': self.signData(app_import)}
            info['signature'] = signature.get('si')

            info['app_import'] = "%s&%s" % (app_import,
                                            urllib.urlencode(signature))
            self.info = info

            #  setup new state
            self.addToTokenInfo('rollout', '2')
            self.enable(True)

        log.debug('[_rollout_2]:')
        return

    def getOcraSuiteSuite(self):
        '''
        getQROcraSuiteSuite - return the QR Ocra Suite
                            - if none, it will return the default

        :return: Ocrasuite of token
        :rtype: string
        '''
        log.debug('[getOcraSuiteSuite]')

        defaultOcraSuite = getFromConfig("OcraDefaultSuite",
                                         'OCRA-1:HOTP-SHA256-8:C-QN08')
        self.ocraSuite = self.getFromTokenInfo('ocrasuite', defaultOcraSuite)

        log.debug('[getOcraSuiteSuite] %r:' % (self.ocraSuite))
        return self.ocraSuite

    def getQROcraSuiteSuite(self):
        '''
        getQROcraSuiteSuite - return the QR Ocra Suite
                            - if none, it will return the default

        :return: QROcrasuite of token
        :rtype: string
        '''
        log.debug('[getQROcraSuiteSuite]')

        defaultOcraSuite = getFromConfig("QrOcraDefaultSuite",
                                         'OCRA-1:HOTP-SHA256-8:C-QA64')
        self.ocraSuite = self.getFromTokenInfo('ocrasuite', defaultOcraSuite)

        log.debug('[getQROcraSuiteSuite] %r:' % (self.ocraSuite))
        return self.ocraSuite

    def signData(self, data):
        '''
        sign the received data with the secret key

        :param data: arbitrary string object
        :type param: string

        :return: hexlified signature of the data
        '''
        log.debug('[signData] %r:' % (data))

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)
        signature = ocraSuite.signData(data)

        log.debug('[signData]: %r:' % (signature))
        return signature

    def challenge(self, data, session='', typ='raw', challenge=None):
        '''
        the challenge method is for creating an transaction / challenge object

        remark: the transaction has a maximum lifetime and a reference to
                the OcraSuite token (serial)

        :param data:     data, which is the base for the challenge or None
        :type data:     string or None
        :param session:  session support for ocratokens
        :type session:  string
        :type typ:      define, which kind of challenge base should be used
                         could be raw - take the data input as is
                              (extract chars accordind challenge definition Q)
                         or random    - will generate a random input
                         or hased     - will take the hash of the input data

        :return:    challenge response containing the transcation id and
                    the challenge for the ocrasuite
        :rtype :    tuple of (transId(string), challenge(string))

        '''

        s_data = 'None'
        s_session = 'None'
        s_challenge = 'None'
        if data is not None:
            s_data = data
        if session is not None:
            s_session = session
        if challenge is None:
            s_challenge = challenge

        log.debug('[challenge] %s: %s: %s' % (s_data, s_session, s_challenge))

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)

        if not data:
            typ = 'random'

        if challenge is None:
            if typ == 'raw':
                challenge = ocraSuite.data2rawChallenge(data)
            elif typ == 'random':
                challenge = ocraSuite.data2randomChallenge(data)
            elif typ == 'hash':
                challenge = ocraSuite.data2hashChallenge(data)

        log.debug('[OcraTokenClass] challenge: %r ' % (challenge))

        serial = self.getSerial()
        counter = self.getOtpCount()

        # set the pin onyl in the compliant hashed mode
        pin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            pin = secObj.getKey()

        try:
            param = {}
            param['C'] = counter
            param['Q'] = challenge
            param['P'] = pin
            param['S'] = session
            if ocraSuite.T is not None:
                now = datetime.datetime.now()
                stime = now.strftime("%s")
                itime = int(stime)
                param['T'] = itime

            ''' verify that the data is compliant with the OcraSuitesuite
                and the client is able to calc the otp
            '''
            c_data = ocraSuite.combineData(**param)
            ocraSuite.compute(c_data)

        except Exception as ex:
            log.exception("[OcraTokenClass]")
            raise Exception('[OcraTokenClass] Failed to create ocrasuite'
                            'challenge: %r' % (ex))

        #  save the object
        digits = '0123456789'
        transid = ''
        transactionIdLen = 12

        try:
            transactionIdLen = int(getFromConfig("OcraDefaultSuite", '12'))
        except:
            transactionIdLen = 12
            log.debug("[OcraTokenClass] Failed to set transactionId length"
                      " from config - using fallback %d" % (transactionIdLen))

        #  create a non exisiting challenge
        try:
            while True:
                for _c in range(0, transactionIdLen):
                    transid += urandom.choice(digits)

                chall = OcraTokenClass.getTransaction(transid)
                if chall is None:
                    break

            ddata = ''
            if data is not None:
                ddata = data

            chall = OcraChallenge(transid, typ + ':' + challenge,
                                  serial, typ + ':' + ddata)
            chall.save()

        except Exception as ex:
            #  this might happen if we have a db problem or
            # the uniqnes constrain does not fit
            log.exception("[OcraTokenClass]")
            raise Exception('[OcraTokenClass] Failed to create challenge'
                            ' object: %s' % (ex))

        realms = []
        tokenrealms = self.token.getRealms()
        for realm in tokenrealms:
            realms.append(realm.name)

        url = get_qrtan_url(realms)

        log.debug('[challenge]: %r: %r: %r' % (transid, challenge, url))
        return (transid, challenge, True, url)

    def checkOtp(self, passw, counter, window, options=None):
        '''
        checkOtp - standard callback of linotp to verify the token

        :param passw:      the passw / otp, which has to be checked
        :type passw:       string
        :param counter:    the start counter
        :type counter:     int
        :param  window:    the window, in which the token is valid
        :type  window:     int
        :param options:    options contains the transaction id, eg. if check_t
                           checks one transaction this will support
                           assynchreonous otp checks (when check_t is used)
        :type options:     dict

        :return:           verification counter or -1
        :rtype:            int (-1)

        '''
        log.debug('[checkOtp] %r: %r: %r' % (passw, counter, window))

        ret = -1

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)

        # if we have no transactionid given through the options,
        # we have to retrieve the eldest challenge for this ocra token
        serial = self.getSerial()
        challenges = []

        # set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            ocraPin = secObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if ocraSuite.T is not None:
            defTimeWindow = int(getFromConfig("ocra.timeWindow", 180))
            window = (int(self.getFromTokenInfo('timeWindow', defTimeWindow))
                      / ocraSuite.T)
            defTimeShift = int(getFromConfig("ocra.timeShift", 0))
            timeShift = int(self.getFromTokenInfo("timeShift", defTimeShift))

        if options is None:
            challenges = OcraTokenClass.getTransactions4serial(serial,
                                                               currentOnly=True)

        elif options is not None:
            if type(options).__name__ != 'dict':
                err = ('[chekOtp] "options" not of type dict! %r' %
                       type(options))
                log.error(err)
                raise Exception(err)

            if 'transactionid' in options:
                transid = options.get('transactionid')
                challenges.append(OcraTokenClass.getTransaction(transid))

            elif 'challenge' in options:
                challenges.append(options)

            # due to the added options in checkUserPass, we have to extend
            # the logic here:
            # if no challenges found in between but we have a serial, we catch
            # the open challenges by serial (s.o.)
            if len(challenges) == 0:
                challenges = OcraTokenClass.getTransactions4serial(serial,
                                                                   currentOnly=True)

        if len(challenges) == 0:
            #  verify that there has already been a challenge
            challenges = OcraTokenClass.getTransactions4serial(serial)
            if len(challenges) > 0:
                err = 'No current transaction found!'
                ret = -1
                return ret
            else:
                err = 'No open transaction found!'
                log.error(err)
                if type(options) == dict and 'transactionid' in options:
                    raise Exception(err)
                ret = -1
                return ret

        for ch in challenges:
            challenge = {}

            if isinstance(ch, dict):
                #  transaction less checkOtp
                self.transId = 0
                challenge.update(ch)

            elif type(ch) == OcraChallenge:
                #  preserve transaction context, so we could use this in
                # the status callback
                self.transId = ch.transid
                challenge['challenge'] = ch.challenge
                challenge['transid'] = ch.transid
                challenge['session'] = ch.session

            ret = ocraSuite.checkOtp(passw, counter, window, challenge,
                                     pin=ocraPin, options=options,
                                     timeshift=timeShift)
            log.debug('[checkOtp]: %r' % (ret))

            if ret != -1:
                break

        if -1 == ret:
            #  autosync: test if two consecutive challenges +
            # it's counter match
            ret = self.autosync(ocraSuite, passw, challenge)

        return ret

    def autosync(self, ocraSuite, passw, challenge):
        '''
        try to resync a token automaticaly, if a former and the current
        request failed

        :param  ocraSuite: the ocraSuite of the current Token
        :type  ocraSuite: ocra object
        :param  passw:
        '''
        log.debug('[OcraToken::autosync] %r : %r' % (passw, challenge))
        res = -1

        autosync = False

        try:
            async = getFromConfig("AutoResync")
            if async is None:
                autosync = False
            elif "true" == async.lower():
                autosync = True
            elif "false" == async.lower():
                autosync = False
        except Exception as ex:
            log.exception('autosync check undefined %r' % (ex))
            return res

        ' if autosync is not enabled: do nothing '
        if False == autosync:
            return res

        ##
        # AUTOSYNC starts here
        ##

        counter = self.token.getOtpCounter()
        syncWindow = self.token.getSyncWindow()
        if ocraSuite.T is not None:
            syncWindow = syncWindow / 10

        # set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            ocraPin = secObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if ocraSuite.T is not None:
            timeShift = int(self.getFromTokenInfo("timeShift", 0))

        #timeStepping    = int(ocraSuite.T)

        tinfo = self.getTokenInfo()

        # autosync does only work, if we have a token info, where the
        # last challenge and the last sync-counter is stored
        # if no tokeninfo, we start with a autosync request, thus start the
        # lookup in the sync window

        if 'lChallenge' not in tinfo:
            # run checkOtp, with sync window for the current challenge
            log.info('[OcraToken:autosync] initial sync')
            count_0 = -1
            try:
                otp0 = passw
                count_0 = ocraSuite.checkOtp(otp0, counter, syncWindow,
                                             challenge, pin=ocraPin,
                                             timeshift=timeShift)
            except Exception as ex:
                log.exception(' error during autosync0 %r' % (ex))

            if count_0 != -1:
                tinfo['lChallenge'] = {'otpc': count_0}
                self.setTokenInfo(tinfo)
                log.info('[OcraToken:autosync] initial sync - success: %r' %
                         count_0)

            res = -1
            log.info('[OcraToken:autosync] initial sync done!')

        else:
            # run checkOtp, with sync window for the current challenge
            log.info('[OcraToken:autosync] sync')
            count_1 = -1
            try:
                otp1 = passw
                count_1 = ocraSuite.checkOtp(otp1, counter, syncWindow,
                                             challenge, pin=ocraPin,
                                             timeshift=timeShift)
            except Exception as ex:
                log.exception(' error during autosync1 %r' % (ex))

            if count_1 == -1:
                del tinfo['lChallenge']
                self.setTokenInfo(tinfo)
                log.info('[OcraToken:autosync] sync failed! Not a valid pass'
                         ' in scope (%r)' % (otp1))
                res = -1
            else:
                # run checkOtp, with sync window for the old challenge
                lChallange = tinfo.get('lChallenge')
                count_0 = lChallange.get('otpc')

                if ocraSuite.C is not None:
                    #  sync the counter based ocra token
                    if count_1 - count_0 < 2:
                        self.setOtpCount(count_1)
                        res = count_1

                if ocraSuite.T is not None:
                    #  sync the timebased ocra token
                    if count_1 - count_0 < ocraSuite.T * 2:
                        # calc the new timeshift !
                        log.debug("[autosync] the counter %r matches: %r" %
                                  (count_1,
                                   datetime.datetime.fromtimestamp(count_1)))

                        currenttime = int(time.time())
                        new_shift = (count_1 - currenttime)

                        tinfo['timeShift'] = new_shift
                        self.setOtpCount(count_1)
                        res = count_1

                #  if we came here, the old challenge is not required anymore
                del tinfo['lChallenge']
                self.setTokenInfo(tinfo)

            log.info('[OcraToken:autosync] sync done!')

        log.debug('[autosync]: %r ' % (res))
        return res

    def is_challenge_response(self, passw, user, options=None,
                              challenges=None):
        '''
        check, if the request contains the result of a challenge

        :param passw: password, which might be pin or pin+otp
        :param user: the requesting user
        :param options: dictionary of additional request parameters

        :return: returns true or false
        '''

        challenge_response = False

        return challenge_response

    def statusValidationFail(self):
        '''
        statusValidationFail - callback to enable a status change,

        will be called if the token verification has failed

        :return - nothing

        '''
        log.debug('[statusValidationFail]')
        ocraChallenge = None

        if self.transId == 0:
            return

        try:
            ocraChallenge = OcraTokenClass.getTransaction(self.transId)
            ocraChallenge.setTanStatus(received=True, valid=False)

            #  still in rollout state??
            rolloutState = self.getFromTokenInfo('rollout', '0')

            if rolloutState == '1':
                log.info('rollout state 1 for token %r not completed'
                         % (self.getSerial()))

            elif rolloutState == '2':
                try:
                    maxchall = int(getFromConfig("OcraMaxChallengeRequests",
                                                 '3'))
                except:
                    maxchall = 3

                if int(ocraChallenge.received_count) >= maxchall:
                    #  after 3 fails in rollout state 2 - reset to rescan
                    self.addToTokenInfo('rollout', '1')
                    log.info('rollout for token %r reset to phase 1:'
                             % (self.getSerial()))

                log.info('rollout for token %r not completed'
                         % (self.getSerial()))

        except Exception as ex:
            log.exception('[OcraTokenClass:statusValidationFail] Error'
                          ' during validation finalisation for token %r :%r'
                          % (self.getSerial(), ex))
            raise Exception(ex)

        finally:
            if ocraChallenge is not None:
                ocraChallenge.save()

        log.debug('[statusValidationFail]')
        return

    def statusValidationSuccess(self):
        '''
        statusValidationSuccess - callback to enable a status change,

        remark: will be called if the token shas been succesfull verified

        :return: - nothing

        '''
        log.debug('[statusValidationSuccess]')

        if self.transId == 0:
            return

        ocraChallenge = OcraTokenClass.getTransaction(self.transId)
        ocraChallenge.setTanStatus(received=True, valid=True)
        ocraChallenge.save()

        #  still in rollout state??
        rolloutState = self.getFromTokenInfo('rollout', '0')

        if rolloutState == '2':
            t_info = self.getTokenInfo()
            if 'rollout' in t_info:
                del t_info['rollout']
            if 'sharedSecret' in t_info:
                del t_info['sharedSecret']
            if 'nonce' in t_info:
                del t_info['nonce']
            self.setTokenInfo(t_info)

            log.info('rollout for token %r completed' % (self.getSerial()))

        elif rolloutState == '1':
            raise Exception('unable to complete the rollout ')

        log.debug('[statusValidationSuccess]:')
        return

    def resync(self, otp1, otp2, options=None):
        '''
        - for the resync to work, we take the last two transactions and
          their challenges
        - for each challenge, we search forward the sync window length

        '''
        log.debug('[resync] %r : %r' % (otp1, otp2))

        ret = False
        challenges = []

        o_challenges = OcraTokenClass.getTransactions4serial(self.getSerial())
        for challenge in o_challenges:
            challenges.append(challenge)

        #  check if there are enough challenges around
        if len(challenges) < 2:
            return False

        challenge1 = {}
        challenge2 = {}

        if options is None:
            ch1 = challenges[0]
            challenge1['challenge'] = ch1.challenge
            challenge1['transid'] = ch1.transid
            challenge1['session'] = ch1.session

            ch2 = challenges[1]
            challenge2['challenge'] = ch2.challenge
            challenge2['transid'] = ch2.transid
            challenge2['session'] = ch2.session

        else:
            if 'challenge1' in options:
                challenge1['challenge'] = options.get('challenge1')
            if 'challenge2' in options:
                challenge2['challenge'] = options.get('challenge2')

        if len(challenge1) == 0 or len(challenge2) == 0:
            error = "No challeges found!"
            log.error('[OcraTokenClass:resync] %s' % (error))
            raise Exception('[OcraTokenClass:resync] %s' % (error))

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)

        syncWindow = self.token.getSyncWindow()
        if ocraSuite.T is not None:
            syncWindow = syncWindow / 10

        counter = self.token.getOtpCounter()

        # set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            ocraPin = secObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if ocraSuite.T is not None:
            timeShift = int(self.getFromTokenInfo("timeShift", 0))

        try:

            count_1 = ocraSuite.checkOtp(otp1, counter, syncWindow,
                                         challenge1, pin=ocraPin,
                                         timeshift=timeShift)
            if count_1 == -1:
                log.info('[resync] lookup for first otp value failed!')
                ret = False
            else:
                count_2 = ocraSuite.checkOtp(otp2, counter, syncWindow,
                                             challenge2, pin=ocraPin,
                                             timeshift=timeShift)
                if count_2 == -1:
                    log.info('[resync] lookup for second otp value failed!')
                    ret = False
                else:
                    if ocraSuite.C is not None:
                        if count_1 + 1 == count_2:
                            self.setOtpCount(count_2)
                            ret = True

                    if ocraSuite.T is not None:
                        if count_1 - count_2 <= ocraSuite.T * 2:
                            #  callculate the timeshift
                            date = datetime.datetime.fromtimestamp(count_2)
                            log.info('[resync] syncing token to new timestamp:'
                                     ' %r' % (date))

                            now = datetime.datetime.now()
                            stime = now.strftime("%s")
                            timeShift = count_2 - int(stime)
                            self.addToTokenInfo('timeShift', timeShift)
                            ret = True

        except Exception as ex:
            log.exception('[OcraTokenClass:resync] unknown error: %r' % (ex))
            raise Exception('[OcraTokenClass:resync] unknown error: %s' % (ex))

        log.debug('[resync]: %r ' % (ret))
        return ret

    def getStatus(self, transactionId):
        '''
        getStatus - assembles the status of a transaction / challenge in a dict

        {   "serial": SERIENNUMMER1,
            "transactionid": TRANSACTIONID1,
            "received_tan": true,
            "valid_tan": true,
            "failcount": 0
        }

        :param transactionId:    the transaction / challenge id
        :type transactionId:    string

        :return:    status dict
        :rtype:       dict
        '''

        log.debug('[getStatus] %r' % (transactionId))

        statusDict = {}
        ocraChallenge = OcraTokenClass.getTransaction(transactionId)
        if ocraChallenge is not None:
            statusDict['serial'] = ocraChallenge.tokenserial
            statusDict['transactionid'] = ocraChallenge.transid
            statusDict['received_tan'] = ocraChallenge.received_tan
            statusDict['valid_tan'] = ocraChallenge.valid_tan
            statusDict['failcount'] = self.getFailCount()
            statusDict['id'] = ocraChallenge.id
            statusDict['timestamp'] = unicode(ocraChallenge.timestamp)
            statusDict['active'] = unicode(self.isActive())

        log.debug('[getStatus]: %r' % (statusDict))
        return statusDict

    @classmethod
    def timeoutJanitor(cls):
        '''
        timeoutJanitor - remove all outdated transactions / challenges

        :return: - nothing

        '''
        log.debug('[timeoutJanitor]')

        delta = datetime.timedelta(days=0)
        scopeDef = getFromConfig("OcraChallengeTimeout", '1D')

        #  timedelta supports : days[, seconds[, microseconds[, milliseconds[,
        # minutes[, hours[, weeks]]]]]]])
        if re.match('^(\d+[DHMS])+$', scopeDef):
            delta = datetime.timedelta(days=0)
            parts = re.findall('\d+[DHMS]', scopeDef)
            for part in parts:
                period = part[-1]
                quantity = int(part[:-1])
                if period == 'D':
                    delta = delta + datetime.timedelta(days=quantity)
                elif period == 'H':
                    delta = delta + datetime.timedelta(hours=quantity)
                elif period == 'M':
                    delta = delta + datetime.timedelta(minutes=quantity)
                elif period == 'S':
                    delta = delta + datetime.timedelta(seconds=quantity)
        else:
            log.info('OcraChallengeTimeout value %r does not match timedelta'
                     ' definition (^(\d+[DHMS])+$)' % (scopeDef))
            try:
                scope_def = int(scopeDef)
                delta = datetime.timedelta(seconds=scope_def)
            except ValueError:
                log.info('Failed to convert OcraChallengeTimeout value from'
                         ' config: %r' % (scopeDef))
                delta = datetime.timedelta(days=1)

        ocraChallenges = Session.query(OcraChallenge).filter(
            OcraChallenge.timestamp < datetime.datetime.now()
            - delta)

        for ocraChallenge in ocraChallenges:
            log.warning("[OcraToken:timeoutJanitor] - dropping outdated"
                        " ocraChallenge): %r for token %r" %
                        (ocraChallenge.transid, ocraChallenge.tokenserial))
            Session.delete(ocraChallenge)

        log.debug('[timeoutJanitor]')
        return

    @classmethod
    def maxChallengeRequestJanitor(cls):
        '''
        maxChallengeRequestJanitor - remove all transactions / challenges
                                     which have been made more than
                                     maxChallengeRequests

        :return: - nothing

        '''
        log.debug('[maxChallengeRequestJanitor]')

        maxRequests = int(getFromConfig("OcraMaxChallengeRequests", '3'))

        ocraChallenges = Session.query(OcraChallenge).filter(
            OcraChallenge.received_count >= maxRequests)

        for ocraChallenge in ocraChallenges:
            log.warning("[OcraToken:timeoutJanitor] - dropping outdated"
                        " ocraChallenge): %r for token %r"
                        % (ocraChallenge.transid, ocraChallenge.tokenserial))
            Session.delete(ocraChallenge)

        log.debug('[maxChallengeRequestJanitor]')
        return

    @classmethod
    def maxChallengeJanitor(cls, transId=None, serial=None):
        '''
        maxChallengeJanitor - remove for one token (serial) all challengens
                              but the last ones

        :param transId:     the current transaction, which provides a
                            the lookup for the serial number
        :type transId:     string

        :param serial:     the serial number of the token
        :type serial:     string

        :return: - nothing

        '''
        log.debug('[maxChallengeJanitor] %r : %r' % (transId, serial))

        maxChallDef = getFromConfig("OcraMaxChallenges", '3')
        try:
            ones = int(maxChallDef)
        except ValueError as ex:
            log.exception('[OcraTokrenClass:maxChallengeJanitor] Faild to'
                          'convert OcraMaxChallenges value from config: %r :%r'
                          % (maxChallDef, ex))
            ones = 3

        if ones <= 0:
            ones = 3

        if transId is not None:
            challenges = Session.query(OcraChallenge).filter(
                OcraChallenge.transid == u'' + transId)
            if challenges is None:
                log.info('[OcraTokrenClass:maxChallengeJanitor] no'
                         ' ocraChallenge found for tranid %r' % (transId))
                return

            for challenge in challenges:
                serial = challenge.tokenserial

        if serial is None:
            log.error('[OcraTokrenClass:maxChallengeJanitor] failed to lookup'
                      ' for transid %r or serial %r' % (transId, serial))
            return

        challenges = Session.query(OcraChallenge).\
            filter(OcraChallenge.tokenserial == u'' + serial)\
            .order_by(desc(OcraChallenge.id))

        lastIds = set()
        for challenge in challenges:
            if len(lastIds) < ones:
                lastIds.add(challenge.id)
            else:
                log.warning("[OcraToken:maxChallengeJanitor] - dropping max"
                            " ocraChallenges: %r :: %r for token %r"
                            % (challenge.id, challenge.transid,
                                challenge.tokenserial))
                Session.delete(challenge)

        log.debug('[maxChallengeJanitor]')
        return

    @classmethod
    def getTransaction(cls, transId):
        '''
        getTransaction - lookup for the challenge object of the given id

        :param transId:   challenge identifier
        :type transId:   string

        :return: the challenge data object
        :rtype: OcraChallenge

        '''
        log.debug('[getTransaction] %r' % (transId))

        #  first do housekeeping - remove outdated transactions
        cls.timeoutJanitor()
        cls.maxChallengeRequestJanitor()
        cls.maxChallengeJanitor(transId=transId)

        ocraChallenge = None
        count = 0

        if transId is not None:
            challenges = Session.query(OcraChallenge).filter(
                OcraChallenge.transid == u'' + transId)

        if challenges is None:
            log.info('no ocraChallenge found for tranid %r' % (transId))
            return None

        for ocraChallenge in challenges:
            log.debug("[OcraSuite:getTransactionId] %r for token: %r"
                      % (ocraChallenge.transid, ocraChallenge.tokenserial))
            count += 1

        if count == 0 or count > 1:
            log.error('%r ocraChallenge token found for this transaction %r '
                      % (count, transId))

        log.debug('[getTransaction] %r' % (ocraChallenge))
        return ocraChallenge

    @classmethod
    def getTransactions4serial(cls, serial, currentOnly=False):
        '''
        getTransactions4serial - give all challenges for a
                                 given token serial number

        :param serial:     token serial identifier
        :type serial:     string
        :param currentOnly: boolean Flag to return all Challenges
                            (like for status request)
                             or to return the eldest open
                             transaction / challenge
        :type currentOnly: boolean flag

        :return:         return a list of Challenges
        :rtype:         OcraChallenge obejct list

        '''
        log.debug('[getTransactions4serial] %r: %r' % (serial, currentOnly))

        #  first do housekeeping - remove outdated transactions
        cls.timeoutJanitor()
        cls.maxChallengeRequestJanitor()
        cls.maxChallengeJanitor(serial=serial)

        ocraChallenges = []
        ocraChallenge = None
        challenges = []

        if serial is not None:
            if currentOnly is False:
                challenges = Session.query(OcraChallenge)\
                    .filter(OcraChallenge.tokenserial == u'' + serial)\
                    .order_by(desc(OcraChallenge.id))
            else:
                #  return the oldest transaction onyl -  orderby(id).limit(1)
                challenges = Session.query(OcraChallenge)\
                    .filter(OcraChallenge.tokenserial == u'' + serial)\
                    .filter(OcraChallenge.received_tan is False)\
                    .order_by(asc(OcraChallenge.id))

        if challenges is None:
            log.info('no ocraChallenge found for serial %r' % (serial))
            return None

        for ocraChallenge in challenges:
            log.debug("[OcraSuite:getTransactionId] %r for token: %r"
                      % (ocraChallenge.transid, ocraChallenge.tokenserial))
            ocraChallenges.append(ocraChallenge)

        log.debug('[getTransactions4serial]')
        return ocraChallenges

    def getInitDetail(self, params, user=None):
        '''
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        '''

        _ = context['translate']

        response_detail = {}

        info = self.getInfo()
        # add : app_import, serial and sharedsecret
        response_detail.update(info)

        otpkey = None
        if 'otpkey' in info:
            otpkey = info.get('otpkey')

        if otpkey is not None:
            response_detail["otpkey"] = {
                "order": '1',
                "description": _("OTP seed"),
                "value": "seed://%s" % otpkey,
                "img": create_img(otpkey, width=200),
            }

        ocra_url = info.get('app_import')

        response_detail["ocraurl"] = {
            "order": '0',
            "description": _("URL for OCRA token"),
            "value": ocra_url,
            "img": create_img(ocra_url, width=250),
        }

        return response_detail

    def getQRImageData(self, response_detail):
        '''
        '''
        url = None
        hparam = {}

        if response_detail is not None:
            if 'ocraurl' in response_detail:
                url = response_detail.get('ocraurl', {}).get('value', '')
                hparam['alt'] = response_detail.get('app_import', '')
        return url, hparam


# eof #########################################################################
