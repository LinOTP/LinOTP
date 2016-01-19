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
library for monitoring controller
"""

import datetime
from linotp.lib.resolver import splitResolver

from linotp.model import Token, Realm, TokenRealm
from linotp.model import Config as config_model
from linotp.model.meta import Session

from linotp.lib.config import LinOtpConfig, storeConfig, getFromConfig

from linotp.lib.useriterator import iterate_users

from linotp.lib.user import getUserListIterators, getUserFromParam

from sqlalchemy import and_, not_


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

    def get_allowed_realms(self, action):
        """
        Get all realms to which user has access.

        If a realm is specified in parm,
        check if user has access to it and return it.
        Else return all possible realms.

        :param action: the policy action which must be checked
        :type action: unicode
        :return: list of realms that user may access
        """

        user = self.context['AuthUser'].get('login', '')
        action = unicode(action)

        # parse policies and extract realms:
        realm_whitelist = []
        for pol in self.context['Policies'].itervalues():
            if pol['active'] == u'True':
                if action in pol['action'] and pol['scope'] == u'monitoring':
                    if user in pol['user'] or pol['user'] is u'*':
                        # TODO: darf man * in die Realms rein schreiben???
                        # Was ist bei ungültigen Eingaben?
                        pol_realms = pol['realm'].split(u',')
                        for rlm in pol_realms:
                            if rlm:
                                realm_whitelist.append(rlm.strip(" ").lower())

        # If there are no policies for us, we are allowed to see all realms
        if not realm_whitelist:
            realm_whitelist = self.context['Realms'].keys()

        return realm_whitelist

    def get_sync_status(self):
        """
        check if cache and config db are synced

        if sync is True, the synctime is returned
        :return: dict with keys 'sync' and 'synctime'
        """
        result = {'sync': False}

        linotp_conf = LinOtpConfig()
        linotp_time = linotp_conf.get('linotp.Config')

        # get db entry for config
        entry = Session.query(config_model).filter(
            config_model.Key == 'linotp.Config').one()
        db_time = entry.Value

        # if the times are not in syc, LinOTP keeps its status
        # cached but does not update its timestamp of sync
        if db_time == linotp_time:
            result['sync'] = True
            result['synctime'] = db_time

        return result

    def get_config_info(self):
        """
        get some counts from config db
        :return: dict with keys 'total', 'ldapresolver', 'sqlresolver',
            'passwdresolver', 'policies', 'realms'
        """
        result = {}
        # the number of config entries
        result['total'] = Session.query(config_model).count()

        # the number of resolver defintions
        ldap = Session.query(config_model).filter(
            config_model.Key.like('linotp.ldapresolver.%')).count()
        result['ldapresolver'] = ldap / 13

        sql = Session.query(config_model).filter(
            config_model.Key.like('linotp.sqlresolver.%')).count()
        result['sqlresolver'] = sql / 12

        passwd = Session.query(config_model).filter(
            config_model.Key.like('linotp.passwdresolver.%')).count()
        result['passwdresolver'] = passwd

        # the number of policy definitions
        policies = Session.query(config_model).filter(
            config_model.Key.like('linotp.Policy.%')).count()
        result['policies'] = policies / 7

        # the number of realm definition (?)
        realms = Session.query(config_model).filter(
            config_model.Key.like('linotp.useridresolver.group.%')).count()
        result['realms'] = realms

        return result

    def get_active_tokencount(self):
        """
        get the number of active tokens from all realms (including norealm)

        :return: number of active tokens
        """
        active = Token.LinOtpIsactive == True
        token_active = Session.query(Token).filter(active).count()
        return token_active

    def check_encryption(self):
        """
        check if a value, which got written into config, got encrypted
        :return:
        """
        test_key = 'linotp.testkey'

        linotp_conf = LinOtpConfig()

        if test_key not in linotp_conf:
            storeConfig(test_key, '', typ='password', desc=None)

        old_value = getFromConfig(test_key, defVal=None)

        now = datetime.datetime
        new_value_plain = str(now)

        storeConfig(test_key, new_value_plain, typ='password', desc=None)

        new_value_enc = getFromConfig(test_key, defVal=None)

        # if new_value_enc != old_value: something new was written into db
        # if new_value_enc != new_value_plain: the new value got encrypted
        if new_value_enc and new_value_plain != new_value_enc != old_value:
            return True

        return False

    def resolverinfo(self, realm):
        """
        get the resolvers for one realm and the number of users per resolver
        :param realm: the realm to query
        :return: dict with resolvernames as keys and number of users as value
        """
        realminfo = self.context.get('Config').getRealms().get(realm)
        resolvers = realminfo.get('useridresolver', '')
        realmdict = {}

        for resolver in resolvers:
            package, module, classs, conf = splitResolver(resolver)
            realmdict[conf] = 0

        user = getUserFromParam({'realm': realm}, optionalOrRequired=True)
        users_iters = iterate_users(getUserListIterators({'realm': realm}, user))

        for next_one in users_iters:
            for key in realmdict:
                if key in next_one:
                    realmdict[key] += 1

        return realmdict
