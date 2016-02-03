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
""" validation processing logic"""

from hashlib import sha256

from sqlalchemy import and_
from sqlalchemy import desc

from linotp.lib.user import getUserId

import linotp.lib.token
import linotp.lib.policy

from linotp.model import Challenge
from linotp.lib.config  import getFromConfig
from linotp.lib.resolver import getResolverObject

import linotp.model.meta
Session = linotp.model.meta.Session

import logging
log = logging.getLogger(__name__)


def get_challenges(serial=None, transid=None):
    '''
    get_challenges - give all challenges for a given token

    :param serial:   serial of the token
    :param transid:  transaction id, if None, all will be retrieved
    :return:         return a list of challenge dict
    '''
    log.debug('[get_challenges] %r' % (serial))

    challenges = []
    if transid is None and serial is None:
        return challenges

    if transid is None:
        db_challenges = Session.query(Challenge)\
            .filter(Challenge.tokenserial == u'' + serial)\
            .order_by(desc(Challenge.id))\
            .all()
    else:
        transid_len = int(getFromConfig('TransactionIdLength', 12))
        if len(transid) == transid_len:
            db_challenges = Session.query(Challenge)\
                .filter(Challenge.transid == transid)\
                .all()
        else:
            db_challenges = Session.query(Challenge)\
                .filter(Challenge.transid.startswith(transid))\
                .all()

    challenges.extend(db_challenges)

    log.debug('[getTransactions4serial] %r' % challenges)
    return challenges


def is_same_transaction(challenge, transaction_id):
    """
    helper method to check if challenge belongs to transaction set

    :param challenge: a challenge object
    :param transaction_id: the transaction id form the request

    :return: boolean
    """
    c_id = challenge.getTransactionId()
    if c_id == transaction_id:
        return True
    elif '.' in c_id:
        (transid, postfix) = c_id.split('.')
        if transid == transaction_id and len(postfix) == 2:
            return True
    return False


def create_challenge(token, options=None, challenge_id=None, id_postfix=''):
    """
    dedicated method to create a challenge to support the implementation
    of challenge policies in future

    :param options: optional parameters for token specific tokens
                    eg. request a signed challenge
    :return: a tuple of  (boolean, and a dict, which contains the
             {'challenge' : challenge} description)
    """

    # response dict, describing the challenge reply
    challenge = {}
    # the allocated db challenge object
    challenge_obj = None
    retry_counter = 0
    reason = None

    id_length = int(getFromConfig('TransactionIdLength', 12)) - len(id_postfix)

    while True:
        try:
            if not challenge_id:
                transactionid = "%s%s" % (Challenge.createTransactionId(
                                                            length=id_length),
                                                            id_postfix)
            else:
                transactionid = challenge_id

            num_challenges = Session.query(Challenge).\
                    filter(Challenge.transid == transactionid).count()

            if num_challenges == 0:
                challenge_obj = Challenge(transid=transactionid,
                                                tokenserial=token.getSerial())
            if challenge_obj is not None:
                break

        except Exception as exce:
            log.info("Failed to create Challenge: %r", exce)
            reason = exce

        # prevent an unlimited loop
        retry_counter = retry_counter + 1
        if retry_counter > 100:
            log.info("Failed to create Challenge for %d times: %r -quiting!",
                     retry_counter, reason)
            raise Exception('Failed to create challenge %r' % reason)

    challenges = get_challenges(serial=token.getSerial())

    # carefully create a new challenge
    try:

        # we got a challenge object allocated and initialize the challenge
        (res, open_transactionid, message, attributes) = \
                             token.initChallenge(transactionid,
                                                 challenges=challenges,
                                                 options=options)

        if res is False:
            # if a different transid is returned, this indicates, that there
            # is already an outstanding challenge we can refere to
            if open_transactionid != transactionid:
                transactionid = open_transactionid

        else:
            # in case the init was successfull, we preserve no the challenge
            # data to support the implementation of a blocking based on the
            # previous stored data
            challenge_obj.setChallenge(message)
            challenge_obj.save()

            (res, message, data, attributes) = \
                        token.createChallenge(transactionid, options=options)

            if res is True:
                # persist the final challenge data + message
                challenge_obj.setChallenge(message)
                challenge_obj.setData(data)
                challenge_obj.save()
            else:
                transactionid = ''

    except Exception as exce:
        reason = exce
        res = False

    # if something goes wrong with the challenge, remove it
    if res is False and challenge_obj is not None:
        try:
            log.debug("deleting session")
            Session.delete(challenge_obj)
            Session.commit()
        except Exception as exx:
            log.debug("deleting session failed: %r" % exx)
            try:
                Session.expunge(challenge_obj)
                Session.commit()
            except Exception as exx:
                log.debug("expunge session failed: %r" % exx)

    # in case that create challenge fails, we must raise this reason
    if reason is not None:
        message = "%r" % reason
        log.error("Failed to create or init challenge %r " % reason)
        raise reason

    # prepare the response for the user
    if transactionid is not None:
        challenge['transactionid'] = transactionid

    if message is not None:
        challenge['message'] = message

    if attributes is not None and type(attributes) == dict:
        challenge.update(attributes)

    return (res, challenge)


def delete_challenges(serial, challenges):
    '''
    delete some challenges of a token

    :param serial: the serial number of the token
    :param challenges: list of (dict|int|str|challenge objects)

    :return: result of the delete operation
    '''

    challenge_ids = []
    for challenge in challenges:
        if type(challenge) == dict:
            if 'id' in challenge:
                challenge_id = challenge.get('id')
        elif type(challenge) == Challenge:
            challenge_id = challenge.get('id')
        elif type(challenge) in (unicode, str, int):
            challenge_id = challenge

        try:
            challenge_ids.append(int(challenge_id))
        except ValueError:
            # ignore
            log.warning("failed to convert the challengeId %r to int()" %
                        challenge_id)

    res = 1
    # gather all challenges with one sql 'in' statement
    if len(challenge_ids) > 0:
        del_challes = Session.query(Challenge).\
            filter(Challenge.tokenserial == serial).\
            filter(Challenge.id.in_(challenge_ids)).all()

        # and delete them via session
        for dell in del_challes:
            Session.delete(dell)

    return res


def check_pin(token, passw, user=None, options=None):
    '''
    check the provided pin w.r.t. the policy definition

    :param passw: the to be checked pass
    :param user: if otppin==1, this is the user, which resolver should
                 be checked
    :param options: the optional request parameters

    :return: boolean, if pin matched True
    '''
    res = False
    pin_policies = linotp.lib.policy.get_pin_policies(user)

    if 1 in pin_policies:
        # We check the Users Password as PIN
        log.debug("pin policy=1: checking the users password as pin")
        # this should not be the case
        if not options:
            options = {}

        if 'pin_match' not in options:
            options['pin_match'] = {}

        hashed_passw = sha256(passw).hexdigest()

        # if password already found, we can return result again
        if hashed_passw in options['pin_match']:
            log.debug("check if password already checked! %r " %
                      options['pin_match'][hashed_passw])
            return options['pin_match'][hashed_passw]

        # if a password already matched, this one will fail
        if 'found' in options['pin_match']:
            log.debug("check if password already found but its not this one!")
            return False

        if user is None or not user.login:
            log.info("fail for pin policy == 1 with user = None")
            res = False
        else:
            (uid, _resolver, resolver_class) = getUserId(user)
            resolver = getResolverObject(resolver_class)
            if resolver.checkPass(uid, passw):
                log.debug("Successfully authenticated user %r." % uid)
                res = True
            else:
                log.info("user %r failed to authenticate." % uid)

        # we register our result
        key = sha256(passw).hexdigest()
        options['pin_match'][key] = res
        # and register the success, to shorten lookups after
        # already one positive was found
        if res is True:
            options['pin_match']['found'] = True

    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug("[__checkToken] pin policy=2: checking no pin")
        if len(passw) == 0:
            res = True
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug("[__checkToken] pin policy=0: checkin the PIN")
        res = token.checkPin(passw, options=options)

    return res


def check_otp(token, otpval, options=None):
    '''
    check the otp value

    :param otpval: the to be checked otp value
    :param options: the additional request parameters

    :return: result of the otp check, which is
            the matching otpcounter or -1 if not valid
    '''

    log.debug("[check_otp] entering function check_otp()")
    log.debug("[check_otp] token  : %r" % token)
    # This is only the OTP value, not the OTP PIN
    log.debug("[check_otp] OtpVal : %r" % otpval)

    counter = token.getOtpCount()
    window = token.getOtpCountWindow()

    res = token.checkOtp(otpval, counter, window, options=options)
    return res


def split_pin_otp(token, passw, user=None, options=None):
    '''
    split the pin and the otp fron the given password

    :param passw: the to be splitted password
    :param options: currently not used, but might be forwarded to the
                    token.splitPinPass
    :return: tuple of (split status, pin and otpval)
    '''
    pin_policies = linotp.lib.policy.get_pin_policies(user)

    policy = 0

    if 1 in pin_policies:
        log.debug("[split_pin_otp] pin policy=1: checking the "
                                                "users password as pin")
        # split the passw into password and otp value
        (pin, otp) = token.splitPinPass(passw)
        policy = 1
    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug("[split_pin_otp] pin policy=2: checking no pin")
        (pin, otp) = ("", passw)
        policy = 2
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug("[split_pin_otp] pin policy=0: checkin the PIN")
        (pin, otp) = token.splitPinPass(passw)

    res = policy
    return (res, pin, otp)


class ValidateToken(object):
    '''
    class to manage the validation of a token
    '''

    class Context(object):
        '''
        little helper class to prove the interface calls valid
        '''
        def __init__(self):
            '''
            initlize the only api member
            '''
            self.audit = {}

    def __init__(self, token, user=None, context=None):
        '''
        ValidateToken constructor

        :param token: the to checked token
        :param user: the user of the check request of the token user
        :param context: this is used to preserve the context, which is used
                        to not import the global c
        '''
        self.token = token
        self.user = user

        # these lists will be returned as result of the token check
        self.challenge_token = []
        self.pin_matching_token = []
        self.invalid_token = []
        self.valid_token = []
        self.related_challenges = []

        # support of context : c.audit
        if context == None:
            self.context = self.Context()
        else:
            self.context = context

    def get_verification_result(self):
        '''
        return the internal result representation of the token verification
        which are a set of list, which stand for the challenge, pinMatching
        or invalid or valid token list

        - the lists are returned as they easily could be joined into the final
          token list, independent of they are empty or contain a token obj

        :return: tuple of token lists
        '''

        return (self.challenge_token, self.pin_matching_token,
                self.invalid_token, self.valid_token)

    def checkToken(self, passw, user, options=None):
        '''
        validate a token against the provided pass

        :raises: "challenge not found",
                 if a state is given and no challenge is found for this
                 challenge id

        :param passw: the password, which could either be a pin, a pin+otp
                       or otp
        :param user: the user which the token belongs to
        :param options: dict with additional request parameters

        :return: tuple of otpcounter and potential reply
        '''
        log.debug("entering function checkToken(%r)" % self.token)
        res = -1
        if options is None:
            options = {}

        # fallback in case of check_s, which does not provide a user
        # but as for further prcessing a dummy user with only the realm defined
        # is required for the policy evaluation
        if user is None:
            user = self.get_token_realm_user()

        # standard authentication token
        if self.token.is_auth_only_token(user):
            (res, reply) = self.check_authenticate(user, passw,
                                                   options=options)
            return (res, reply)

        # only challenge response token authentication
        if not self.token.is_challenge_and_auth_token(user):

            # first check are there outstanding challenges
            challenges = self.get_challenges(options)
            if self.token.is_challenge_response(passw, user,
                                                options=options,
                                                challenges=challenges):

                (res, reply) = self.check_challenge_response(challenges,
                                                             user, passw,
                                                             options=options)
                return (res, reply)

            res = self.token.is_challenge_request(passw, user, options=options)
            if res:
                self.challenge_token.append(self.token)
            else:
                self.invalid_token.append(self.token)

            return (False, None)

        # else: tokens, which support both: challenge response
        # and standard authentication

        # first check are there outstanding challenges
        challenges = self.get_challenges(options)
        if self.token.is_challenge_response(passw, user,
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
        res = self.token.is_challenge_request(passw, user, options=options)
        if res:
            self.challenge_token.append(self.token)
        else:
            self.invalid_token.append(self.token)

        return (False, None)

    def check_challenge_response(self, challenges, user, passw, options=None):
        '''
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
        '''
        # challenge reply will stay None as we are in the challenge response
        # mode
        reply = None
        if not options:
            options = {}

        otp = passw

        (otpcount, matching_challenges) = self.token.checkResponse4Challenge(
                                            user, otp, options=options,
                                            challenges=challenges)
        if otpcount >= 0:
            self.valid_token.append(self.token)
            if len(self.invalid_token) > 0:
                del self.invalid_token[0]
        else:
            self.invalid_token.append(self.token)

        self.free_challenges(matching_challenges)

        return (otpcount, reply)

    def free_challenges(self, matching_challenges):
        # delete all challenges, which belong to the token and
        # the token could decide on its own, which should be deleted
        # default is: challenges which are younger than the matching one
        # are to be deleted

        all_challenges = self.lookup_challenge()
        to_be_deleted = self.token.challenge_janitor(matching_challenges,
                                                     all_challenges)

        # gather all related challenges, which as well must be deleted.
        # (related by the means of having a '.dd' postfix in transaction id)
        # These are then retrieved in the outer loop to call for each token
        # the challenge janitor so that every token may decide which challenge
        # to delete
        for del_challenge in to_be_deleted:
            if '.' in del_challenge.transid:
                tran_id = del_challenge.transid.split('.')[0]
                related_challenges = get_challenges(transid=tran_id)
                self.related_challenges.extend(related_challenges)

        delete_challenges(serial=self.token.getSerial(),
                          challenges=to_be_deleted)

        return

    def get_token_realm_user(self):

        user = None
        realms = linotp.lib.token.getTokenRealms(self.token.getSerial())
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

        pin_match, otp_count, reply = self.token.authenticate(passw, user,
                                                              options=options)
        if otp_count >= 0:
            self.valid_token.append(self.token)
        elif pin_match is True:
            self.pin_matching_token.append(self.token)
        else:
            self.invalid_token.append(self.token)

        return (otp_count, reply)

    def get_challenges(self, options=None):
        '''
        get all challenges, defined either by the option=state
        or identified by the token serial reference

        :param options: the request options

        :return: a list of challenges
        '''
        challenges = []
        valid_challenges = []

        if (options is not None and
            "state" in options or "transactionid" in options):
            state = options.get('state', options.get('transactionid'))

            challenges = self.lookup_challenge(serial=self.token.getSerial(),
                                               state=state)
            if len(challenges) == 0 and self.token.getType() not in ['ocra']:
                # if state argument is given, but no open challenge found
                # this might be a problem, so make a log entry
                log.info('no challenge with state %s found for %s'
                            % (state, self.token.getSerial()))

        else:
            challenges = self.lookup_challenge(serial=self.token.getSerial())

        # now verify that the challenge is valid
        for ch in challenges:
            if self.token.is_challenge_valid(ch):
                valid_challenges.append(ch)

        return valid_challenges

    def lookup_challenge(self, serial=None, state=None):
        '''
        database lookup to find all challenges belonging to a token and or
        if exist with a transaction state

        :param state: the optional parameter identified the state/transactionId

        :return: the list of challenges
        '''

        conditions = ()
        if serial:
            conditions += (and_(Challenge.tokenserial == serial),)
        if state:
            transid_len = int(getFromConfig('TransactionIdLength', 12))
            if len(state) == transid_len:
                conditions += (and_(Challenge.transid == state),)
            else:
                conditions += (and_(Challenge.transid.startswith(state)),)

        # SQLAlchemy requires the conditions in one arg as tupple
        condition = and_(*conditions)
        challenges = Session.query(Challenge).filter(condition).all()
        return challenges



#eof###########################################################################
