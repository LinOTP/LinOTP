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
""" contains the tokeniterator """

ENCODING = "utf-8"

import re
import logging
import fnmatch

try:
    import json
except ImportError:
    import simplejson as json

from sqlalchemy import or_, and_, not_

import linotp
from linotp.lib.error import UserError

from linotp.lib.token import (getTokenRealms,
                              getTokens4UserOrSerial,
                              getAllTokenUsers
                              )
from linotp.lib.user import getUserId, getUserInfo
from linotp.lib.user import User
from linotp.lib.realm import getRealms

from linotp.model import Token
from linotp.model import Realm, TokenRealm
from linotp.model.meta import Session

from linotp.lib.config  import getFromConfig


log = logging.getLogger(__name__)
class TokenIterator(object):
    '''
    TokenIterator class - support a smooth iterating through the tokens
    '''

    def _get_serial_condition(self, serial, allowed_realm):
        """
        add condition for a given serial

        :param serial: serial number of token
        :param allowed_realm: the allowed realms
        """
        scondition = None

        if serial is None:
            return scondition

        # check if the requested serial is
        # in the realms of the admin (filterRealm)
        allowed = False
        if "*" in allowed_realm:
            allowed = True
        else:
            realms = getTokenRealms(serial)
            for realm in realms:
                if realm in allowed_realm:
                    allowed = True

        # if we have a serial and no realm, we return a un-resolvable condition
        if serial and not allowed:
            scondition = and_(Token.LinOtpTokenSerialnumber == '')
            return scondition

        if "*" in serial:
            like_serial = serial.replace("*", "%")
            scondition = and_(Token.LinOtpTokenSerialnumber.like(like_serial))
        else:
            scondition = and_(Token.LinOtpTokenSerialnumber == serial)

        return scondition

    def _get_user_condition(self, user, valid_realms):

        ucondition = None

        if not user or user.is_empty or not user.login:
            return ucondition

        loginUser = user.login.lower()
        loginUser = loginUser.replace('"', '')
        loginUser = loginUser.replace("'", '')

        searchType = "any"
        ## search for a 'blank' user
        if len(loginUser) == 0 and len(user.login) > 0:
            searchType = "blank"
        elif loginUser == "/:no user:/" or loginUser == "/:none:/":
            searchType = "blank"
        elif loginUser == "/:no user info:/":
            searchType = "wildcard"
        elif "*" in loginUser:
            searchType = "wildcard"
        else:
            ## no blank and no wildcard search
            searchType = "exact"

        if searchType == "blank":
            ucondition = and_(or_(Token.LinOtpUserid == u'',
                                  Token.LinOtpUserid is None))

        if searchType == "exact":
            serials = []
            users = []

            # if search for a realmuser 'user@realm' we can take the
            # realm from the argument
            if len(user.realm) > 0:
                users.append(user)
            else:
                # otherwise we add all users which are possible combinations
                # from loginname and entry of the valid realms.
                # In case of a '*' wildcard in the list, we take all available
                # realms
                if '*' in valid_realms:
                    valid_realm_list = getRealms().keys()
                else:
                    valid_realm_list = valid_realms

                for realm in valid_realm_list:
                    users.append(User(user.login, realm))

            # resolve the realm with wildcard:
            # identify all users and add these to the userlist
            userlist = []
            for usr in users:
                urealm = usr.realm
                if urealm == '*':
                    # if the realm is set to *, the getUserId
                    # triggers the identification of all resolvers, where the
                    # user might reside: trigger the user resolver lookup
                    for realm in getRealms().keys():
                        if realm in valid_realms or '*' in valid_realms:
                            usr.realm = realm
                            try:
                                (_uid, _resolver, _resolverClass) = getUserId(usr)
                            except UserError as exx:
                                log.info('User %r not found in realm %r',
                                         usr, realm)
                                continue
                            userlist.extend(usr.getUserPerConf())
                else:
                    userlist.append(usr)

            for usr in userlist:
                try:
                    tokens = getTokens4UserOrSerial(user=usr, _class=False)
                    for tok in tokens:
                        serials.append(tok.LinOtpTokenSerialnumber)
                except UserError as ex:
                    ## we get an exception if the user is not found
                    log.debug('[TokenIterator::init] no exact user: %r'
                              % (user))
                    log.debug('[TokenIterator::init] %r' % ex)

            if len(serials) > 0:
                # if tokens found, search for their serials
                ucondition = and_(Token.LinOtpTokenSerialnumber.in_(serials))
            else:
                # if no token is found, block search for user
                # and return nothing
                ucondition = and_(Token.LinOtpTokenSerialnumber == u'')

        ## handle case, when nothing found in former cases
        if searchType == "wildcard":
            serials = []
            users = getAllTokenUsers()
            logRe = None
            lU = loginUser.replace('*', '.*')
            #lU = lU.replace('..', '.')
            logRe = re.compile(lU)

            for ser in users:
                userInfo = users.get(ser)
                tokenUser = userInfo.get('username').lower()
                try:
                    if logRe.match(u'' + tokenUser) is not None:
                        serials.append(ser)
                except Exception as e:
                    log.error('error no express %r ' % e)

            ## to prevent warning, we check is serials are found
            ## SAWarning: The IN-predicate on
            ## "Token.LinOtpTokenSerialnumber" was invoked with an
            ## empty sequence. This results in a contradiction, which
            ## nonetheless can be expensive to evaluate.  Consider
            ## alternative strategies for improved performance.
            if len(serials) > 0:
                ucondition = and_(Token.LinOtpTokenSerialnumber.in_(serials))
            else:
                ucondition = and_(Token.LinOtpTokenSerialnumber == u'')
        return ucondition

    def _get_filter_confition(self, filter):
        conditon = None

        if filter is None:
            condition = None
        elif filter in ['/:active:/', '/:enabled:/',
                        '/:token is active:/', '/:token is enabled:/' ]:
            condition = and_(Token.LinOtpIsactive is True)
        elif filter in ['/:inactive:/', '/:disabled:/',
                        '/:token is inactive:/', '/:token is disabled:/']:
            condition = and_(Token.LinOtpIsactive is False)
        else:
            # search in other colums
            filter = linotp.lib.crypto.uencode(filter)
            condition = or_(Token.LinOtpTokenDesc.contains(filter),
                            Token.LinOtpIdResClass.contains(filter),
                            Token.LinOtpTokenSerialnumber.contains(filter),
                            Token.LinOtpUserid.contains(filter),
                            Token.LinOtpTokenType.contains(filter))
        return condition

    def _get_realm_condition(self, valid_realms, filterRealm):
        """
         create the condition for only getting certain realms!
        """
        rcondition = None
        if '*' in valid_realms:
            log.debug("[TokenIterator::init] wildcard for realm '*' found."
                      " Tokens of all realms will be displayed")
            return rcondition

        if len(valid_realms) > 0:
            log.debug("[TokenIterator::init] adding filter condition"
                      " for realm %r" % valid_realms)

            # get all matching realms
            token_ids = self._get_tokens_in_realm(valid_realms)
            rcondition = and_(Token.LinOtpTokenId.in_(token_ids))
            return rcondition

        if ("''" in filterRealm or '""' in filterRealm or
              "/:no realm:/" in filterRealm):
            log.debug("[TokenIterator::init] search for all tokens, which are"
                      " in no realm")

            # get all tokenrealm ids
            token_id_tuples = Session.query(TokenRealm.token_id).all()
            token_ids = set()
            for token_tuple in token_id_tuples:
                token_ids.add(token_tuple[0])

            ## define the token id not condition
            rcondition = and_(not_(Token.LinOtpTokenId.in_(token_ids)))
            return rcondition

        if filterRealm:
            # get all matching realms
            search_realms = set()

            realms = getRealms()
            for realm in realms:
                for frealm in filterRealm:
                    if fnmatch.fnmatch(realm, frealm):
                        search_realms.add(realm)

            search_realms = list(search_realms)

            # define the token id condition
            token_ids = self._get_tokens_in_realm(search_realms)
            rcondition = and_(Token.LinOtpTokenId.in_(token_ids))
            return rcondition

        return rcondition

    def _get_tokens_in_realm(self, valid_realms):
        ## get all matching realms
        realm_id_tuples = Session.query(Realm.id).\
                            filter(Realm.name.in_(valid_realms)).all()
        realm_ids = set()
        for realm_tuple in realm_id_tuples:
            realm_ids.add(realm_tuple[0])
        ## get all tokenrealm ids
        token_id_tuples = Session.query(TokenRealm.token_id).\
                    filter(TokenRealm.realm_id.in_(realm_ids)).all()
        token_ids = set()
        for token_tuple in token_id_tuples:
            token_ids.add(token_tuple[0])

        return token_ids

    def _convert_realms_to_resolvers(self, valid_realms):
        """
        it's easier and more efficient to look for the resolver definition in
        one realm, than to follow the join on database level
        """
        resolvers = set()
        realms = getRealms()
        if '*' in valid_realms:
            search_realms = realms.keys()
        else:
            search_realms = valid_realms

        for realm in search_realms:
            resolvers.update(realms.get(realm, {}).get('useridresolver', []))

        return list(resolvers)

    def __init__(self, user, serial, page=None, psize=None, filter=None,
                 sort=None, sortdir=None, filterRealm=None, user_fields=None,
                 params=None):
        '''
        constructor of Tokeniterator, which gathers all conditions to build
        a sqalchemy query - iterator

        :param user:     User object - user provides as well the searchfield entry
        :type  user:     User class
        :param serial:   serial number of a token
        :type  serial:   string
        :param page:     page number
        :type  page:     int
        :param psize:    how many entries per page
        :type  psize:    int
        :param filter:   additional condition
        :type  filter:   string
        :param sort:     sort field definition
        :type  sort:     string
        :param sortdir:  sort direction: ascending or descending
        :type  sortdir:  string
        :param filterRealm:  restrict the set of token to those in the filterRealm
        :type  filterRealm:  string or list
        :param user_fields:  list of additional fields from the user owner
        :type  user_fields: array
        :param params:  list of additional request parameters - currently not used
        :type  params: dict

        :return: - nothing / None

        '''

        if params is None:
            params = {}

        self.page = 1
        self.pages = 1
        self.tokens = 0

        self.user_fields = user_fields
        if self.user_fields is None:
            self.user_fields = []

        if type(filterRealm) in (str, unicode):
            filterRealm = filterRealm.split(',')

        if type(filterRealm) in [list]:
            s_realms = []
            for f in filterRealm:
                #  support for multiple realm filtering in the ui
                #  as a coma separated string
                for s_realm in f.split(','):
                    s_realms.append(s_realm.strip())
            filterRealm = s_realms

        #  create a list of all realms, which are allowed to be searched
        #  based on the list of the existing ones
        valid_realms = []
        realms = getRealms().keys()
        if '*' in filterRealm:
            valid_realms.append("*")
        else:
            for realm in realms:
                if realm in filterRealm:
                    realm = linotp.lib.crypto.uencode(realm)
                    valid_realms.append(realm)

        scondition = self._get_serial_condition(serial, filterRealm)
        ucondition = self._get_user_condition(user, valid_realms)
        fcondition = self._get_filter_confition(filter)
        rcondition = self._get_realm_condition(valid_realms, filterRealm)

        #  create the final condition as AND of all conditions
        condTuple = ()
        for conn in (fcondition, ucondition, scondition, rcondition):
            if type(conn).__name__ != 'NoneType':
                condTuple += (conn,)

        condition = and_(*condTuple)

        order = Token.LinOtpTokenDesc

        #   o LinOtp.TokenId: 17943
        #   o LinOtp.TokenInfo: ""
        #   o LinOtp.TokenType: "spass"
        #   o LinOtp.TokenSerialnumber: "spass0000FBA3"
        #   o User.description: "User Name,linotp@keyidentity.com,local,"
        #   o LinOtp.IdResClass: "useridresolver.PasswdIdResolver.IdResolver._default_Passwd_"
        #   o User.username: "user"
        #   o LinOtp.TokenDesc: "Always Authenticate"
        #   o User.userid: "1000"
        #   o LinOtp.IdResolver: "/etc/passwd"
        #   o LinOtp.Isactive: true

        if sort == "TokenDesc":
            order = Token.LinOtpTokenDesc
        elif sort == "TokenId":
            order = Token.LinOtpTokenId
        elif sort == "TokenType":
            order = Token.LinOtpTokenType
        elif sort == "TokenSerialnumber":
            order = Token.LinOtpTokenSerialnumber
        elif sort == "TokenType":
            order = Token.LinOtpTokenType
        elif sort == "IdResClass":
            order = Token.LinOtpIdResClass
        elif sort == "IdResolver":
            order = Token.LinOtpIdResolver
        elif sort == "Userid":
            order = Token.LinOtpUserid
        elif sort == "FailCount":
            order = Token.LinOtpFailCount
        elif sort == "Userid":
            order = Token.LinOtpUserid
        elif sort == "Isactive":
            order = Token.LinOtpIsactive

        #  care for the result sort order
        if sortdir is not None and sortdir == "desc":
            order = order.desc()
        else:
            order = order.asc()

        #  care for the result pageing
        if page is None:
            self.toks = Session.query(Token).filter(condition).order_by(order).distinct()
            self.tokens = self.toks.count()

            log.debug("[TokenIterator] DB-Query returned # of objects: %i" % self.tokens)
            self.pagesize = self.tokens
            self.it = iter(self.toks)
            return

        try:
            if psize is None:
                pagesize = int(getFromConfig("pagesize", 50))
            else:
                pagesize = int(psize)
        except:
            pagesize = 20

        try:
            thePage = int (page) - 1
        except:
            thePage = 0
        if thePage < 0:
            thePage = 0

        start = thePage * pagesize
        stop = (thePage + 1) * pagesize

        self.toks = Session.query(Token).filter(condition).order_by(order).distinct()
        self.tokens = self.toks.count()
        log.debug("[TokenIterator::init] DB-Query returned # of objects: %i" % self.tokens)
        self.page = thePage + 1
        fpages = float(self.tokens) / float(pagesize)
        self.pages = int(fpages)
        if fpages - int(fpages) > 0:
            self.pages = self.pages + 1
        self.pagesize = pagesize
        self.toks = self.toks.slice(start, stop)

        self.it = iter(self.toks)

        return

    def getResultSetInfo(self):
        resSet = {"pages"   : self.pages,
                  "pagesize" : self.pagesize,
                  "tokens"  : self.tokens,
                  "page"    : self.page}
        return resSet

    def getUserDetail(self, tok):
        userInfo = {}
        uInfo = {}

        userInfo["User.description"] = u''
        userInfo["User.userid"] = u''
        userInfo["User.username"] = u''
        for field in self.user_fields:
            userInfo["User.%s" % field] = u''

        if tok.LinOtpUserid:
            # userInfo["User.description"]    = u'/:no user info:/'
            userInfo["User.userid"] = u'/:no user info:/'
            userInfo["User.username"] = u'/:no user info:/'

            uInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver, tok.LinOtpIdResClass)
            if uInfo is not None and len(uInfo) > 0:
                if uInfo.has_key("description"):
                    description = uInfo.get("description")
                    if isinstance(description, str):
                        userInfo["User.description"] = description.decode(ENCODING)
                    else:
                        userInfo["User.description"] = description

                if uInfo.has_key("userid"):
                    userid = uInfo.get("userid")
                    if isinstance(userid, str):
                        userInfo["User.userid"] = userid.decode(ENCODING)
                    else:
                        userInfo["User.userid"] = userid

                if uInfo.has_key("username"):
                    username = uInfo.get("username")
                    if isinstance(username, str):
                        userInfo["User.username"] = username.decode(ENCODING)
                    else:
                        userInfo["User.username"] = username

                for field in self.user_fields:
                    fieldvalue = uInfo.get(field, "")
                    if isinstance(fieldvalue, str):
                        userInfo["User.%s" % field] = fieldvalue.decode(ENCODING)
                    else:
                        userInfo["User.%s" % field] = fieldvalue

        return (userInfo, uInfo)

    def next(self):

        tok = self.it.next()
        desc = tok.get_vars(save=True)
        ''' add userinfo to token description '''
        (userInfo, ret) = self.getUserDetail(tok)
        desc.update(userInfo)

        return desc

    def __iter__(self):
        return self

# eof #########################################################################
