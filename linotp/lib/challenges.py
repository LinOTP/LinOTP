# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

import datetime
import functools
import json
import logging

from flask import g
from sqlalchemy import and_, desc

import linotp
from linotp.lib.cache_utils import cache_in_request
from linotp.lib.context import request_context as context
from linotp.model import db
from linotp.model.challange import Challenge

log = logging.getLogger(__name__)


class Challenges(object):
    DefaultTransactionIdLength = 17

    @staticmethod
    def get_transactionid_length():
        """
        get transaction id length from config and check if it is in range
        :return: length of transaction id
        """
        transid_len = int(
            context.get("Config", {}).get(
                "TransactionIdLength", Challenges.DefaultTransactionIdLength
            )
        )

        if transid_len < 12 or transid_len > 17:
            raise Exception(
                "TransactionIdLength must be between 12 and 17, was %d" % transid_len
            )
        return transid_len

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
        log.debug("lookup_challenges: serial %r: transactionid %r", serial, transid)

        if transid is None and serial is None:
            log.debug(
                "lookup_challenges was called without serial or "
                "transid! Returning all challenges"
            )

        conditions = ()

        if transid:
            transid_len = Challenges.get_transactionid_length()

            if len(transid) == transid_len:
                conditions += (and_(Challenge.transid == transid),)
            else:
                conditions += (and_(Challenge.transid.startswith(transid + ".")),)

        if serial:
            conditions += (and_(Challenge.tokenserial == serial),)

        if filter_open is True:
            conditions += (and_(Challenge.session.like('%"status": "open"%')),)

        challenges = (
            Challenge.query.filter(*conditions).order_by(desc(Challenge.id)).all()
        )

        log.debug("lookup_challenges: founnd challenges: %r", challenges)

        return challenges

    @staticmethod
    def create_challenge(token, options=None, challenge_id=None, id_postfix=""):
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
        ReasonException = Exception()

        hsm = context["hsm"].get("obj")

        transid_len = Challenges.get_transactionid_length()

        id_length = transid_len - len(id_postfix)

        while True:
            try:
                if not challenge_id:
                    transactionid = "%s%s" % (
                        Challenge.createTransactionId(length=id_length),
                        id_postfix,
                    )
                else:
                    transactionid = challenge_id

                num_challenges = Challenge.query.filter_by(
                    transid=transactionid
                ).count()

                if num_challenges == 0:
                    challenge_obj = Challenge(
                        transid=transactionid, tokenserial=token.getSerial()
                    )
                if challenge_obj is not None:
                    break

            except Exception as exce:
                log.error("Failed to create challenge: %r", exce)
                reason = "%r" % exce
                ReasonException = exce

            # prevent an unlimited loop
            retry_counter = retry_counter + 1
            if retry_counter > 100:
                log.error(
                    "Failed to create challenge for %d times: %r - quiting!",
                    retry_counter,
                    reason,
                )
                raise Exception("Failed to create challenge %r" % reason)

        expired_challenges, valid_challenges = Challenges.get_challenges(token)

        # carefully create a new challenge
        try:
            # we got a challenge object allocated and initialize the challenge
            (
                res,
                open_transactionid,
                message,
                attributes,
            ) = token.initChallenge(
                transactionid, challenges=valid_challenges, options=options
            )

            if res is False:
                # if a different transid is returned, this indicates, that there
                # is already an outstanding challenge we can refere to
                if open_transactionid != transactionid:
                    transactionid = open_transactionid

            else:
                # in case the init was successful, we preserve no the
                # challenge data to support the implementation of a blocking
                # based on the previous stored data
                challenge_obj.setChallenge(message)
                challenge_obj.save()

                (res, message, data, attributes) = token.createChallenge(
                    transactionid, options=options
                )

                if res is True:
                    # persist the final challenge data + message
                    challenge_obj.setChallenge(message)
                    challenge_obj.setData(data)
                    challenge_obj.signChallenge(hsm)
                    challenge_obj.save()
                else:
                    transactionid = ""
                    reason = message
                    ReasonException = Exception(message)

        except Exception as exce:
            log.error("Failed to create challenge: %r", exce)
            reason = "%r" % exce
            ReasonException = exce
            res = False

        # if something goes wrong with the challenge, remove it
        if res is False and challenge_obj is not None:
            try:
                log.debug(
                    "Deleting challenge from database session, because of earlier error"
                )
                db.session.delete(challenge_obj)
                db.session.commit()
            except Exception as exx:
                log.debug(
                    "Deleting challenge from database session failed. "
                    "Retrying with expunge. Exception was: %r",
                    exx,
                )
                try:
                    db.session.expunge(challenge_obj)
                    db.session.commit()
                except Exception as exx:
                    log.debug(
                        "Expunging challenge from database session "
                        "failed. Exception was: %r",
                        exx,
                    )

        # in case that create challenge fails, we must raise this reason
        if reason is not None:
            log.error("Failed to create or init challenge. Reason was %r ", reason)
            raise ReasonException

        # prepare the response for the user
        if transactionid is not None:
            challenge["transactionid"] = transactionid

        if message is not None:
            challenge["message"] = message

        if attributes is not None and isinstance(attributes, dict):
            challenge.update(attributes)

        #
        # add token specific info like tokentype, serial and description
        #

        challenge["linotp_tokenserial"] = token.getSerial()
        challenge["linotp_tokentype"] = token.type
        try:
            challenge["linotp_tokendescription"] = token.token.LinOtpTokenDesc
        except:
            challenge["linotp_tokendescription"] = None

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
            if isinstance(challenge, dict):
                if "id" in challenge:
                    challenge_id = challenge.get("id")
            elif isinstance(challenge, Challenge):
                challenge_id = challenge.get("id")
            elif isinstance(challenge, (str, int)):
                challenge_id = challenge

            try:
                challenge_ids.append(int(challenge_id))
            except ValueError:
                # ignore
                log.warning(
                    "failed to convert the challenge id %r to integer",
                    challenge_id,
                )

        res = 1
        # gather all challenges with one sql 'in' statement
        if len(challenge_ids) > 0:
            conditions = ()
            if serial:
                conditions += (and_(Challenge.tokenserial == serial),)

            conditions += (and_(Challenge.id.in_(challenge_ids)),)

            del_challes = Challenge.query.filter(*conditions).all()

            # and delete them via session
            for dell in del_challes:
                db.session.delete(dell)

        return res

    def _get_challenges_cache_keygen(
        token=None, transid=None, options=None, filter_open=False
    ):
        """
        takes exactly the same parameters as get_challanges
        and produces a key for keeping the return value of get_challanges
        in the cache
        In this case the only problem is the token object which we will
        replace by the token serial
        """
        token_key = token.getSerial() if token else None
        options_key = str(options)
        return json.dumps((token_key, transid, options_key, filter_open))

    @staticmethod
    @cache_in_request(key_generator=_get_challenges_cache_keygen)
    def get_challenges(token=None, transid=None, options=None, filter_open=False):
        state = options and options.get("state", options.get("transactionid"))

        if not transid:
            transid = state

        if not token and not transid:
            raise Exception("unqualified query")

        serial = token and token.getSerial()

        challenges = Challenges.lookup_challenges(serial=serial, transid=transid)

        expired_challenges = []
        valid_chalenges = []

        for challenge in challenges:
            if filter_open and not challenge.is_open():
                log.info("Skipping non-open challenge: %r", challenge)
                continue

            if not Challenges.verify_checksum(challenge):
                # as broken challenges are security relvant, we log this
                # and make this visible to the system administrator by
                # appending a message in audit log detail.

                msg = " Checksum verification failure for challenge %r."

                log.error(msg, challenge.transid)

                g.audit["action_detail"] = g.audit.get("action_detail", "") + (
                    msg % challenge.transid
                )
                continue

            # lookup the validty time of the challenge which is per token
            serial = challenge.tokenserial
            token = linotp.lib.token.get_token(serial)
            validity = token.get_challenge_validity()

            c_start_time = challenge.get("timestamp")
            c_expire_time = c_start_time + datetime.timedelta(seconds=validity)
            c_now = datetime.datetime.now()
            if c_now > c_expire_time:
                expired_challenges.append(challenge)
            elif filter_open and challenge.is_open():
                # if we want to see only the open challenges, we check so :)
                valid_chalenges.append(challenge)
            elif not filter_open:
                valid_chalenges.append(challenge)

        return expired_challenges, valid_chalenges

    @staticmethod
    def handle_related_challenge(matching_challenges):
        """
        handle related challenges and close these

        :param matching_challenges: all challenges that have
                                    been correctly answered
        """
        from linotp.lib.token import get_token

        to_be_closed_challenges = set()

        for matching_challenge in matching_challenges:
            # gather all challenges which are now obsolete
            # from the token point of view
            serial = matching_challenge.tokenserial
            token = get_token(serial)
            token_challenges = Challenges.lookup_challenges(serial=serial)
            to_be_closed = token.challenge_janitor(
                [matching_challenge], token_challenges
            )
            to_be_closed_challenges.update(to_be_closed)

            # gather all challenges which are part of the same transaction
            transid = matching_challenge.transid
            if "." in transid:
                transid = transid.split(".")[0]
            transid_challenges = Challenges.lookup_challenges(transid=transid)
            to_be_closed_challenges.update(transid_challenges)

        hsm = context["hsm"].get("obj")
        for challenge in to_be_closed_challenges:
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

        hsm = context["hsm"].get("obj")

        # we query for all challenges of the token to identify the valid ones
        expired_challenges, valid_challenges = Challenges.get_challenges(token)

        if success:
            for challenge in token.matching_challenges:
                # set the valid received
                challenge.setTanStatus(received=True, valid=True)

            to_be_closed = token.challenge_janitor(
                token.matching_challenges, valid_challenges
            )

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

        hsm = context["hsm"].get("obj")

        # and calculate the mac for this token data
        result = challenge.checkChallengeSignature(hsm)
        return result


def transaction_id_to_u64(transaction_id):
    """
    converts a transaction_id to u64 format (used in the challenge-url format)
    transaction_ids come in 2 formats:

    - Normal Transaction - 49384
    - Subtransaction - 213123.39

    where the 2 places behind the point start with 01.

    The function converts the strings by "multiplying" it with
    100, so we well get 4938400 and 21312339
    """

    # HACK! remove when transaction id handling is
    # refactored.

    if "." in transaction_id:
        before, _, after = transaction_id.partition(".")
        encoded = before + after
    else:
        encoded = transaction_id + "00"

    return int(encoded)
