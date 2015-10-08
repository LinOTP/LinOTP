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
"""
library for monitoring controller
"""

from linotp.model import Token, Session, Realm, TokenRealm
from sqlalchemy import or_, and_, not_


class MonitorHandler(object):
    """
    provide functions for monitor controller
    """
    def __init__(self, context):
        self.context = context

    def token_per_realm_count(self, realm, status=None):
        """
        Give the number of tokens per realm

        :return a dict with the keys: active, inactive,
            assigned, unassigned, total
        """
        result = {}

        # if no realm or empty realm is specified
        if realm.strip() == '' or realm.strip() == '/:no realm:/':
            #  get all tokenrealm ids
            token_id_tuples = Session.query(TokenRealm.token_id).all()
            token_ids = set()
            for token_tuple in token_id_tuples:
                token_ids.add(token_tuple[0])
            # all tokens, which are not references in TokenRealm
            r_condition = and_(not_(Token.LinOtpTokenId.in_(token_ids)))
        else:
            # otherwise query all items with realm references
            r_condition = and_(TokenRealm.realm_id == Realm.id,
                                Realm.name == u'' + realm,
                                TokenRealm.token_id == Token.LinOtpTokenId)

        result['total'] = Session.query(Token).\
            filter(r_condition).distinct().count()

        if not status:
            return result

        for stat in status:
            conditions = (and_(r_condition),)
            # handle combinations like:
            # status=unassigned&active,unassigned&inactive
            if '&' in stat:
                stati = stat.split('&')
                if 'assigned' in stati:
                    conditions += (and_(Token.LinOtpUserid != u''),)
                else:
                    conditions += (and_(Token.LinOtpUserid == u''),)
                if 'active' in stati:
                    conditions += (and_(Token.LinOtpIsactive == True),)
                else:
                    conditions += (and_(Token.LinOtpIsactive == False),)
            else:
                # handle single expressions like
                # status=unassigned,active
                if 'assigned' == stat:
                    conditions += (and_(Token.LinOtpUserid != u''),)
                elif 'unassigned' == stat:
                    conditions += (and_(Token.LinOtpUserid == u''),)
                elif 'active' == stat:
                    conditions += (and_(Token.LinOtpIsactive == True),)
                elif 'inactive' == stat:
                    conditions += (and_(Token.LinOtpIsactive == False),)

            #  create the final condition as AND of all conditions
            condition = and_(*conditions)
            result[stat] = Session.query(TokenRealm, Realm, Token).\
                            filter(condition).count()

        return result

    def get_allowed_realms(self):
        """
        Get all realms to which user has access.

        If a realm is specified in parm,
        check if user has access to it and return it.
        Else return all possible realms.

        :return: list of realms that user may access
        """
        user = self.context['user'].get('login', '') or ''

        # parse policies and extract realms:
        # TODO: implement scope Monitoring to policies and use them here
        # here: admin policies are used for testing purposes
        realm_whitelist = []
        for pol in self.context['policies'].itervalues():
            if pol['active'] == u'True':
                if u'show' in pol['action'] and pol['scope'] == u'admin':
                    if user in pol['user'] or pol['user'] is u'*':
                        pol_realms = pol['realm'].split(u',')
                        for rlm in pol_realms:
                            if rlm:
                                realm_whitelist.append(rlm.strip(" ").lower())

        # If there are no policies for us, we are allowed to see all realms
        if not realm_whitelist:
            realm_whitelist = self.context['all_realms'].keys()

        return realm_whitelist
