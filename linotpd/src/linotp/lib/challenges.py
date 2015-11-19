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

import logging

from sqlalchemy import desc

import linotp
from linotp.model import Session, Challenge

log = logging.getLogger(__name__)

class Challenges(object):

    @staticmethod
    def transform_challenges(challenges):
        '''
        small helper to transfor a set of DB Challenges to a list
        of challenge data as dicts

        :param challenges: list of database challenges

        :return: a list with challenge data dicts
        '''
        channel_list = []
        for challenge in challenges:
            channel_list.append(challenge.get())
        # return channel_list
        return challenges

    @staticmethod
    def get_challenges(context, serial=None, transid=None):
        '''
        get_challenges - give all challenges for a given token

        :param context:
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
            transid_len = int(context.get('Config').get('TransactionIdLength', 12))
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
    def create_challenge(token, context, options=None, challenge_id=None, id_postfix=''):
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

        id_length = int(context.get('Config', None).get('TransactionIdLength', 12)) - len(id_postfix)

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

        challenges = Challenges.get_challenges(context, serial=token.getSerial())

        # carefully create a new challenge
        try:

            # we got a challenge object allocated and initialize the challenge
            (res, open_transactionid, message, attributes) = \
                                 token.initChallenge(transactionid,
                                                     challenges=challenges,
                                                     options=options)

            if res == False:
                # if a different transid is returned, this indicates, that there
                # is already an outstanding challenge we can refere to
                if open_transactionid != transactionid:
                    transactionid = open_transactionid

            else:
                # in case the init was successfull, we preserve no the challenge data
                # to support the implementation of a blocking based on the previous
                # stored data
                challenge_obj.setChallenge(message)
                challenge_obj.save()

                (res, message, data, attributes) = \
                            token.createChallenge(transactionid, options=options)

                if res == True:
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
        if res == False and challenge_obj is not None:
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

    @staticmethod
    def handle_related_challenge(related_challenges, context):
        # if there are any related challenges, we have to call the
        # token janitor, who decides if a challenge is still valid
        # eg. expired
        for related_challenge in related_challenges:
            serial = related_challenge.tokenserial
            transid = related_challenge.transid
            token = linotp.lib.token.getTokens4UserOrSerial(serial=serial)[0]

            # get all challenges and the matching ones
            all_challenges = Challenges.get_challenges(context, serial=serial)
            matching_challenges = Challenges.get_challenges(context, serial=serial,
                                                 transid=transid)

            # call the janitor to select the invalid challenges
            to_be_deleted = token.challenge_janitor(matching_challenges,
                                                      all_challenges)
            if to_be_deleted:
                Challenges.delete_challenges(serial, to_be_deleted)

        return