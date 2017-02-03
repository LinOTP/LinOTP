# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""
library for monitoring controller
"""

import datetime

from linotp.lib.resolver import parse_resolver_spec

from linotp.model import Token, Realm, TokenRealm
from linotp.model import Config as config_model
from linotp.model.meta import Session


from linotp.lib.config import LinOtpConfig
from linotp.lib.config import storeConfig
from linotp.lib.config import getFromConfig

from linotp.lib.useriterator import iterate_users

from linotp.lib.user import getUserListIterators, getUserList
from linotp.lib.user import getUserFromParam

from linotp.lib.context import request_context as context

from sqlalchemy import (and_, or_, not_)


class MonitorHandler(object):
    """
    provide functions for monitor controller
    """


    def token_count(self, realm_list, status=None):
        """
        Give the number of tokens (with status) per realm
        if multiple tokens are given, give summary for all tokens
        tokens which are in multiple realms are only counted once!

        :param realm_list: list of realms which must be queried
        :param status: string which contains requested token status
        :return: dict with the keys: active, inactive,
            assigned, unassigned, total
        """

        if not isinstance(realm_list, (list, tuple)):
            realms = [realm_list]
        else:
            # copy realms so that we can delete items safely
            realms = realm_list[:]

        if len(realms) < 1:
            realms = ['/:no realm:/']

        result = {}
        cond = tuple()

        for realm in realms:
            realm = realm.strip()
            if '/:no realm:/' in realm or realm == '':
                #  get all tokenrealm ids
                token_id_tuples = Session.query(TokenRealm.token_id).all()
                token_ids = set()
                for token_tuple in token_id_tuples:
                    token_ids.add(token_tuple[0])
                # all tokens, which are not references in TokenRealm
                cond += (and_(not_(Token.LinOtpTokenId.in_(token_ids))),)
                if '/:no realm:/' in realm:
                    realms.remove('/:no realm:/')

            else:
                cond += (and_(TokenRealm.realm_id == Realm.id,
                              Realm.name == realm,
                              TokenRealm.token_id == Token.LinOtpTokenId),)

        # realm condition:
        r_condition = or_(*cond)

        for stat in status:
            if stat == 'total':
                result['total'] = Session.query(Token).filter(r_condition).\
                    distinct().count()
                continue
            conditions = (and_(r_condition),)
            # handle combinations like:
            # status=unassigned&active,unassigned&inactive
            if '&' in stat:
                stati = stat.split('&')
                if 'assigned' in stati:
                    conditions += (and_(Token.LinOtpUserid != ''),)
                else:
                    conditions += (and_(Token.LinOtpUserid == ''),)
                if 'active' in stati:
                    conditions += (and_(Token.LinOtpIsactive == True),)
                else:
                    conditions += (and_(Token.LinOtpIsactive == False),)
            else:
                # handle single expressions like
                # status=unassigned,active
                if 'assigned' == stat:
                    conditions += (and_(Token.LinOtpUserid != ''),)
                elif 'unassigned' == stat:
                    conditions += (and_(Token.LinOtpUserid == ''),)
                elif 'active' == stat:
                    conditions += (and_(Token.LinOtpIsactive == True),)
                elif 'inactive' == stat:
                    conditions += (and_(Token.LinOtpIsactive == False),)

            #  create the final condition as AND of all conditions
            condition = and_(*conditions)
            result[stat] = Session.query(TokenRealm, Realm, Token).\
                filter(condition).count()

        return result

    def get_sync_status(self):
        """
        check if cache and config db are synced

        if sync is True, the synctime is returned
        else, the difference (cache-time - database_time) is given
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
            now = datetime.datetime.now()
            result['now'] = unicode(now)

        else:
            format_string = '%Y-%m-%d %H:%M:%S.%f'
            linotp_t = datetime.datetime.strptime(str(linotp_time), format_string)
            db_t = datetime.datetime.strptime(str(db_time), format_string)
            result['cache_to_db_diff'] = unicode(linotp_t - db_t)
            result['db_time'] = db_time

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

        now = datetime.datetime.now()
        new_value_plain = unicode(now)

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

        realminfo = context.get('Config').getRealms().get(realm)
        resolver_specs = realminfo.get('useridresolver', '')
        realmdict = {}

        for resolver_spec in resolver_specs:
            __, config_identifier = parse_resolver_spec(resolver_spec)
            realmdict[config_identifier] = 0

        user = getUserFromParam({'realm': realm})
        users = getUserList({'realm': realm, 'username': '*'}, user)

        for next_one in users:
            resolver = next_one['useridresolver'].split('.')[-1]
            if resolver in realmdict:
                realmdict[resolver] += 1

        return realmdict

    def active_users_per_realm(self, realm=None):
        """
        get the number of users which are assigned to an active token in total
            or per realm and resolver
        :param realm: name of realm
        :return: dict with
                keys: resolvernames
                values: number of active token users
        """
        realminfo = context.get('Config').getRealms().get(realm)
        resolver_specs = realminfo.get('useridresolver', '')
        realmdict = {}

        for resolver_spec in resolver_specs:
            __, config_identifier = parse_resolver_spec(resolver_spec)
            act_users_per_resolver = Session.query(Token.LinOtpUserid,
                                                   Token.LinOtpIdResolver,
                                                   Token.LinOtpIdResClass,
                                                   Token.LinOtpIsactive)\
                .join(TokenRealm)\
                .join(Realm)\
                .filter(and_(
                            Token.LinOtpIsactive == True,
                            Token.LinOtpIdResClass == resolver_spec,
                            Realm.name == realm
                ))\
                .group_by(Token.LinOtpUserid, Token.LinOtpIdResolver,
                          Token.LinOtpIsactive, Token.LinOtpIdResClass)

            realmdict[config_identifier] = act_users_per_resolver.count()

        return realmdict

    def active_users_total(self, realmlist):
        """
        get the total number of users of active tokens
        for all resolvers which are in allowed realms

        users are counted per resolver, so if resolver is in more than one
        realm, its uers will only be counted once

        :param realmlist: list of (existing and allowed) realms
        :return: number of users in allowed realms who own an active token
        """
        realm_cond = tuple()
        for realm in realmlist:
            realm_cond += (or_(Realm.name == realm),)

        user_and_resolver = Session.query(Token.LinOtpUserid,
                                          Token.LinOtpIdResolver,
                                          Token.LinOtpIdResClass,
                                          Token.LinOtpIsactive)\
            .join(TokenRealm)\
            .join(Realm)\
            .filter(or_(*realm_cond),
                    and_(Token.LinOtpIsactive == True,
                         Token.LinOtpIdResolver != ''))\
            .group_by(Token.LinOtpUserid, Token.LinOtpIdResolver,
                      Token.LinOtpIsactive, Token.LinOtpIdResClass)

        all_server_total = user_and_resolver.count()
        return all_server_total
