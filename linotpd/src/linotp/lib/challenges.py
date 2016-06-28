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

import json
import logging
import datetime

from sqlalchemy import desc, and_
import linotp
from linotp.model import Session
from linotp.model import Challenge
from linotp.lib.context import request_context as context

log = logging.getLogger(__name__)


class Challenges(object):

    @staticmethod
    def lookup_challenges(serial=None, transid=None, filter_open=False):
        """
        database lookup to find all challenges belonging to a token and or
        if exist with a transaction state

        :param serial:   serial of the token
        :param transid:  transaction id, if None, all will be retrieved
        :param filter_open: check only for those challenges, which have not
                            been verified before
        :return:         return a list of challenge dict
        """
        log.debug('serial %r: transactionid %r', serial, transid)

        if transid is None and serial is None:
            log.debug(
                'Called without serial or transid! Returning all challenges')

        conditions = ()

        if transid:
            transid_len = int(
                context.get('Config').get('TransactionIdLength', 12) or 12)

            if len(transid) == transid_len:
                conditions += (and_(Challenge.transid == transid),)
            else:
                conditions += (and_(Challenge.transid.startswith(transid)),)

        if serial:
            conditions += (and_(Challenge.tokenserial == serial),)

        if filter_open is True:
            conditions += (and_(Challenge.session.like('%"status": "open"%')),)

        # SQLAlchemy requires the conditions in one arg as tupple
        condition = and_(*conditions)
        challenges = Session.query(Challenge).\
            filter(condition).order_by(desc(Challenge.id)).all()

        log.debug('%r', challenges)

        return challenges

    @staticmethod
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

    @staticmethod
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

        hsm = context['hsm'].get('obj')

        id_length = int(
            context.get('Config', None).get('TransactionIdLength', 12)) - \
                        len(id_postfix)

        while True:
            try:
                if not challenge_id:
                    transactionid = "%s%s" % (
                    Challenge.createTransactionId(length=id_length), id_postfix)
                else:
                    transactionid = challenge_id

                num_challenges = Session.query(Challenge). \
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
                log.info(
                    "Failed to create Challenge for %d times: %r -quiting!",
                    retry_counter, reason)
                raise Exception('Failed to create challenge %r' % reason)

        expired_challenges, valid_challenges = Challenges.get_challenges(token)

        # carefully create a new challenge
        try:

            # we got a challenge object allocated and initialize the challenge
            (res, open_transactionid, message, attributes) = \
                token.initChallenge(transactionid,
                                    challenges=valid_challenges,
                                    options=options)

            if res is False:
                # if a different transid is returned, this indicates, that there
                # is already an outstanding challenge we can refere to
                if open_transactionid != transactionid:
                    transactionid = open_transactionid

            else:
                # in case the init was successfull, we preserve no the
                # challenge data to support the implementation of a blocking
                # based on the previous stored data
                challenge_obj.setChallenge(message)
                challenge_obj.save()

                (res, message, data, attributes) = \
                    token.createChallenge(transactionid, options=options)

                if res is True:
                    # persist the final challenge data + message
                    challenge_obj.setChallenge(message)
                    challenge_obj.setData(data)
                    challenge_obj.signChallenge(hsm)
                    challenge_obj.save()
                else:
                    transactionid = ''
                    reason = Exception(message)

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

    @staticmethod
    def delete_challenges(serial, challenges):
        """
        delete some challenges of a token

        :param serial: the serial number of the token
        :param challenges: list of (dict|int|str|challenge objects)
        :return: result of the delete operation
        """

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
            conditions = ()
            if serial:
                conditions += (and_(Challenge.tokenserial == serial),)

            conditions += (and_(Challenge.id.in_(challenge_ids)),)

            # SQLAlchemy requires the conditions in one arg as tupple
            condition = and_(*conditions)
            del_challes = Session.query(Challenge).filter(condition).all()

            # and delete them via session
            for dell in del_challes:
                Session.delete(dell)

        return res

    @staticmethod
    def get_challenges(token=None, transid=None, options=None, filter_open=False):

        if not options:
            options = {}

        state = options.get('state', options.get('transactionid', None))
        if not transid:
            transid = state

        if not token and not transid:
            raise Exception("unqualified query")

        # transaction ids are handled preferred
        if transid:
            challenges = Challenges.lookup_challenges(transid=transid)
        elif token:
            challenges = Challenges.lookup_challenges(serial=token.getSerial())
        else:
            challenges = []

        expired_challenges = []
        valid_chalenges = []

        for challenge in challenges:
            # if we should filter the
            if filter_open:
                stat = challenge.is_open()
                if not stat:
                    continue

            # lookup the validty time of the challenge which is per token
            serial = challenge.tokenserial
            tokens = linotp.lib.token.getTokens4UserOrSerial(serial=serial)
            validity = tokens[0].get_challenge_validity()

            c_start_time = challenge.get('timestamp')
            c_expire_time = c_start_time + datetime.timedelta(seconds=validity)
            c_now = datetime.datetime.now()
            if c_now > c_expire_time:
                expired_challenges.append(challenge)
            else:
                # if we want to see only the open challenges, we check so :)
                if filter_open:
                    if challenge.is_open():
                        valid_chalenges.append(challenge)
                else:
                    valid_chalenges.append(challenge)

        return expired_challenges, valid_chalenges

    @staticmethod
    def handle_related_challenge(matching_challenges):
        """
        handle related challenges and close these

        :param matching_challenges: all challenges that have
                                    been correctly answerd
        """
        from linotp.lib.token import getTokens4UserOrSerial

        to_be_closed_challenges = []

        for matching_challenge in matching_challenges:

            # gather all challenges which are now obsolete
            # from the token point of view
            serial = matching_challenge.tokenserial
            token = getTokens4UserOrSerial(serial=serial)[0]
            token_challenges = Challenges.lookup_challenges(serial=serial)
            to_be_closed = token.challenge_janitor([matching_challenge],
                                                   token_challenges)
            to_be_closed_challenges.extend(to_be_closed)

            # gather all challenges which are part of the same transaction
            transid = matching_challenge.transid
            if "." in transid:
                transid = transid.split('.')[0]
            transid_challenges = Challenges.lookup_challenges(transid=transid)
            to_be_closed_challenges.extend(transid_challenges)

        hsm = context['hsm'].get('obj')
        for challenge in set(to_be_closed_challenges):
            challenge.close()
            # and calculate the mac for this token data
            challenge.signChallenge(hsm)
            challenge.save()

        return

    @staticmethod
    def finish_challenges(token, success=False):
        """
        preserve the token challenge status

        :param token: the token where the challenges belong to
        :param success: boolean value to indicate if it was processed
                        successfully or not

        :return: - nothing -
        """

        hsm = context['hsm'].get('obj')

        # we query for all challenges of the token to identify the valid ones
        (expired_challenges,
         valid_challenges) = Challenges.get_challenges(token)

        if success:
            for challenge in token.matching_challenges:
                # set the valid received
                challenge.setTanStatus(received=True, valid=True)

            to_be_closed = token.challenge_janitor(token.matching_challenges,
                                                   valid_challenges)

            all_challenges = to_be_closed + token.matching_challenges

        else:
            all_challenges = valid_challenges

        # we query for all challenges of the token and mark them as closed
        for challenge in all_challenges:

            # first preserve the new status
            if success:
                challenge.close()
            else:
                challenge.setTanStatus(received=True, valid=False)

            # and calculate the mac for this token data
            challenge.signChallenge(hsm)
            challenge.save()

        # finally delete the expired ones
        if expired_challenges:
            Challenges.delete_challenges(None, expired_challenges)

        return

    @staticmethod
    def verify_checksum(challenge):
        """
        verify_checksum
            verify that the challenge data was not modified on db level

        :param challenge: challenge object
        :return: success boolean
        """

        hsm = context['hsm'].get('obj')

        # and calculate the mac for this token data
        result = challenge.checkChallengeSignature(hsm)
        return result
