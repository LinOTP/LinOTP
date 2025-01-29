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
"""contains the tokeniterator"""

import fnmatch
import logging
import re
from difflib import get_close_matches

from flask_sqlalchemy import Pagination
from sqlalchemy import and_, not_, or_

from linotp.lib.config import getFromConfig
from linotp.lib.error import UserError
from linotp.lib.realm import getRealms
from linotp.lib.resolver import getResolverSpecByName
from linotp.lib.token import (
    get_raw_tokens,
    getTokenRealms,
    token_owner_iterator,
)
from linotp.lib.user import NoResolverFound, User, getUserId, getUserInfo
from linotp.model import db
from linotp.model.realm import Realm
from linotp.model.token import Token
from linotp.model.tokenRealm import TokenRealm

ENCODING = "utf-8"


log = logging.getLogger(__name__)


def _compile_regex(search_text):
    """
    :param search_text: compile a regex from the search text
    :return: search regex
    """

    searcH_regex = re.compile(
        "^%s$" % search_text.replace(".", r"\.").replace("*", ".*")
    )

    return searcH_regex


def _compare_regex(regex, compare_string):
    """
    helper function to check if a wildcard search expression
    matches one of the token owners

    :params regex: compiled expression like 'max*@example.*.net
    :params compare_string: the string to be compared

    :return: boolean
    """

    try:
        if compare_string is None:
            return False

        match = regex.match("" + compare_string.lower())
        if match is not None:
            return True

    except Exception as exx:
        log.error("error with regular expression matching %r", exx)

    return False


def _user_expression_match(login_user, token_owner_iterator):
    """
    :param login_user: the user expression we want to match
    :param token_owner_iterator: tuple iterator of (serial an owner_name)

    :return: list of serials
    """

    # create regex
    user_search_expression = _compile_regex(login_user)

    # compare for each owner
    serials = [
        serial
        for serial, owner in token_owner_iterator
        if _compare_regex(user_search_expression, owner)
    ]
    return serials


class TokenIterator(object):
    """
    TokenIterator class - support a smooth iterating through the tokens
    """

    def __init__(
        self,
        user,
        serial,
        page=None,
        psize=None,
        filter=None,
        sort=None,
        sortdir=None,
        filterRealm=None,
        user_fields=None,
        params=None,
    ):
        """
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
        :param params:  dict of additional request parameters - currently: user_id, resolver_name
        :type  params: dict

        :return: - nothing / None

        """

        if params is None:
            params = {}

        self.page = 1
        self.pages = 1
        self.total_token_count = 0

        self.user_fields = user_fields or []

        if isinstance(filterRealm, str):
            filterRealm = filterRealm.split(",")

        if type(filterRealm) in [list]:
            #  support for multiple realm filtering in the ui
            #  as a coma separated string
            filterRealm = [
                realm.strip() for f in filterRealm for realm in f.split(",")
            ]

        #  create a list of all realms, which are allowed to be searched
        #  based on the list of the existing ones
        valid_realms = (
            ["*"]
            if "*" in filterRealm
            else [realm for realm in filterRealm if realm in getRealms()]
        )

        scondition = self._get_serial_condition(serial, filterRealm)
        ucondition = self._get_user_condition(user, valid_realms)
        fcondition = self._get_filter_condition(filter)
        rcondition = self._get_realm_condition(valid_realms, filterRealm)
        pcondition = self._get_params_condition(params)

        #  create the final condition as AND of all conditions
        condTuple = ()
        for conn in (
            fcondition,
            ucondition,
            scondition,
            rcondition,
            pcondition,
        ):
            if type(conn).__name__ != "NoneType":
                condTuple += (conn,)

        condition = and_(*condTuple)

        order = (
            self._map_sort_param_to_token_param(sort)
            if sort
            else Token.LinOtpTokenDesc
        )

        #  care for the result sort order
        if sortdir is not None and sortdir == "desc":
            order = order.desc()
        else:
            order = order.asc()

        #  care for the result pageing
        if page is None:
            self.tokens = (
                Token.query.filter(condition).order_by(order).distinct()
            )
            self.total_token_count = self.tokens.count()

            log.debug(
                "[TokenIterator] DB-Query returned # of objects: %r",
                self.total_token_count,
            )
            self.pagesize = self.total_token_count
            self.it = iter(self.tokens)
            return

        try:
            if psize is None:
                pagesize = int(getFromConfig("pagesize", 50))
            else:
                pagesize = int(psize)
        except BaseException:
            pagesize = 20

        try:
            requested_page = int(page)
        except BaseException:
            requested_page = 1
        if requested_page < 1:
            requested_page = 1

        paginated_tokens: Pagination = (
            Token.query.filter(condition)
            .order_by(order)
            .distinct()
            .paginate(page=requested_page, per_page=pagesize)
        )

        self.tokens = paginated_tokens.items
        self.total_token_count = paginated_tokens.total
        log.debug(
            "[TokenIterator::init] DB-Query returned # of objects: %r",
            self.tokens,
        )
        self.page = paginated_tokens.page
        self.pages = paginated_tokens.pages
        self.pagesize = pagesize

        self.it = iter(self.tokens)

        return

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
            scondition = and_(Token.LinOtpTokenSerialnumber == "")
            return scondition

        if "*" in serial:
            like_serial = serial.replace("*", "%")
            scondition = and_(Token.LinOtpTokenSerialnumber.like(like_serial))
        else:
            scondition = and_(Token.LinOtpTokenSerialnumber == serial)

        return scondition

    def _get_user_condition(self, user, valid_realms):
        ucondition = None

        if not user:
            return ucondition

        loginUser = user.login.lower().replace('"', "").replace("'", "")

        searchType = "any"
        # search for a 'blank' user
        if len(loginUser) == 0 and len(user.login) > 0:
            searchType = "blank"
        elif loginUser == "/:no user:/" or loginUser == "/:none:/":
            searchType = "blank"
        elif loginUser == "/:no user info:/":
            searchType = "wildcard"
        elif "*" in loginUser:
            searchType = "wildcard"
        else:
            # no blank and no wildcard search
            searchType = "exact"

        if searchType == "blank":
            ucondition = and_(
                or_(
                    Token.LinOtpUserid == "",
                    Token.LinOtpUserid == None,
                )
            )
        elif searchType == "exact":
            serials = []

            # if search for a realmuser 'user@realm' we can take the
            # realm from the argument
            if len(user.realm) > 0:
                users = [user]
            else:
                # otherwise we add all users which are possible combinations
                # from loginname and entry of the valid realms.
                # In case of a '*' wildcard in the list, we take all available
                # realms
                valid_realm_list = (
                    list(getRealms().keys())
                    if "*" in valid_realms
                    else valid_realms
                )
                users = [User(user.login, realm) for realm in valid_realm_list]

            # resolve the realm with wildcard:
            # identify all users and add these to the userlist
            userlist = []
            for usr in users:
                urealm = usr.realm
                if urealm == "*":
                    # if the realm is set to *, the getUserId
                    # triggers the identification of all resolvers, where the
                    # user might reside: trigger the user resolver lookup
                    for realm in list(getRealms().keys()):
                        if realm in valid_realms or "*" in valid_realms:
                            usr.realm = realm
                            try:
                                (_uid, _resolver, _resolverClass) = getUserId(
                                    usr
                                )
                            except UserError as exx:
                                log.info(
                                    "User %r not found in realm %r", usr, realm
                                )
                                continue
                            userlist.extend(usr.getUserPerConf())
                else:
                    userlist.append(usr)

            for usr in userlist:
                try:
                    serials.extend(
                        tok.LinOtpTokenSerialnumber
                        for tok in get_raw_tokens(user=usr)
                    )
                except UserError as ex:
                    # we get an exception if the user is not found
                    log.debug("[TokenIterator::init] no exact user: %r", user)
                    log.debug("[TokenIterator::init] %r", ex)

            if len(serials) > 0:
                # if tokens found, search for their serials
                ucondition = and_(Token.LinOtpTokenSerialnumber.in_(serials))
            else:
                # if no token is found, block search for user
                # and return nothing
                ucondition = and_(Token.LinOtpTokenSerialnumber == "")

        # handle case, when nothing found in former cases
        if searchType == "wildcard":
            serials = _user_expression_match(loginUser, token_owner_iterator())

            # to prevent warning, we check is serials are found
            # SAWarning: The IN-predicate on
            # "Token.LinOtpTokenSerialnumber" was invoked with an
            # empty sequence. This results in a contradiction, which
            # nonetheless can be expensive to evaluate.  Consider
            # alternative strategies for improved performance.

            if len(serials) > 0:
                ucondition = and_(Token.LinOtpTokenSerialnumber.in_(serials))
            else:
                ucondition = and_(Token.LinOtpTokenSerialnumber == "")
        return ucondition

    def _get_filter_condition(self, filter):
        conditon = None

        if filter is None:
            condition = None
        elif filter in [
            "/:active:/",
            "/:enabled:/",
            "/:token is active:/",
            "/:token is enabled:/",
        ]:
            condition = and_(Token.LinOtpIsactive == True)
        elif filter in [
            "/:inactive:/",
            "/:disabled:/",
            "/:token is inactive:/",
            "/:token is disabled:/",
        ]:
            condition = and_(Token.LinOtpIsactive == False)
        else:
            # search in other colums
            condition = or_(
                Token.LinOtpTokenDesc.contains(filter),
                Token.LinOtpIdResClass.contains(filter),
                Token.LinOtpTokenSerialnumber.contains(filter),
                Token.LinOtpUserid.contains(filter),
                Token.LinOtpTokenType.contains(filter),
            )
        return condition

    def _get_realm_condition(self, valid_realms, filterRealm):
        """
        create the condition for only getting certain realms!
        """
        rcondition = None
        if "*" in valid_realms:
            log.debug(
                "[TokenIterator::init] wildcard for realm '*' found."
                " Tokens of all realms will be displayed"
            )
            return rcondition

        if len(valid_realms) > 0:
            log.debug(
                "[TokenIterator::init] adding filter condition"
                " for realm %r",
                valid_realms,
            )

            # get all matching realms
            token_ids = self._get_tokens_in_realm(valid_realms)
            rcondition = and_(Token.LinOtpTokenId.in_(token_ids))
            return rcondition

        if (
            "''" in filterRealm
            or '""' in filterRealm
            or "/:no realm:/" in filterRealm
        ):
            log.debug(
                "[TokenIterator::init] search for all tokens, which are"
                " in no realm"
            )

            return and_(Token.realms == None)

        if filterRealm:
            # get all matching realms
            search_realms = list(
                {
                    realm
                    for frealm in filterRealm
                    for realm in getRealms()
                    if fnmatch.fnmatch(realm, frealm)
                }
            )

            # define the token id condition
            token_ids = self._get_tokens_in_realm(search_realms)
            rcondition = and_(Token.LinOtpTokenId.in_(token_ids))
            return rcondition

        return rcondition

    def _get_params_condition(self, params):
        condTuple = ()

        if params.get("user_id"):
            user_id = params.get("user_id")
            condTuple += (and_(Token.LinOtpUserid == user_id),)

        if params.get("resolver_name"):
            spec = getResolverSpecByName(params.get("resolver_name"))
            condTuple += (and_(Token.LinOtpIdResClass == spec),)

        return and_(*condTuple)

    def _get_tokens_in_realm(self, valid_realms):
        if not valid_realms:
            return set()

        # get all matching realms
        realm_id_tuples = (
            db.session.query(Realm.id)
            .filter(Realm.name.in_(valid_realms))
            .all()
        )
        realm_ids = {realm_tuple[0] for realm_tuple in realm_id_tuples}

        # get all tokenrealm ids
        token_id_tuples = (
            db.session.query(TokenRealm.token_id)
            .filter(TokenRealm.realm_id.in_(realm_ids))
            .all()
        )
        token_ids = {token_tuple[0] for token_tuple in token_id_tuples}

        return token_ids

    def _convert_realms_to_resolvers(self, valid_realms):
        """
        it's easier and more efficient to look for the resolver definition in
        one realm, than to follow the join on database level
        """
        realms = getRealms()
        search_realms = realms.keys() if "*" in valid_realms else valid_realms

        resolvers = {
            realms.get(realm, {}).get("useridresolver", [])
            for realm in search_realms
        }
        return list(resolvers)

    def _map_sort_param_to_token_param(self, sort_param: str):
        mapping = {
            "TokenDesc": Token.LinOtpTokenDesc,
            "TokenId": Token.LinOtpTokenId,
            "TokenType": Token.LinOtpTokenType,
            "TokenSerialnumber": Token.LinOtpTokenSerialnumber,
            "IdResolver": Token.LinOtpIdResolver,
            "IdResClass": Token.LinOtpIdResClass,
            "Userid": Token.LinOtpUserid,
            "FailCount": Token.LinOtpFailCount,
            "Count": Token.LinOtpCount,
            "Isactive": Token.LinOtpIsactive,
            "CreationDate": Token.LinOtpCreationDate,
            "LastAuthMatch": Token.LinOtpLastAuthMatch,
            "LastAuthSuccess": Token.LinOtpLastAuthSuccess,
        }
        try:
            return mapping[sort_param]
        except KeyError:
            error_msg = f"Tokens can't be sorted by {sort_param}."
            potential_sort_params = get_close_matches(
                sort_param, mapping.keys()
            )
            if potential_sort_params:
                error_msg += f" Did you mean any of {potential_sort_params}?"
            raise KeyError(error_msg)

    def getResultSetInfo(self):
        resSet = {
            "pages": self.pages,
            "pagesize": self.pagesize,
            "tokens": self.total_token_count,
            "page": self.page,
        }
        return resSet

    def getUserDetail(self, tok):
        uInfo = {}
        userInfo = {
            "User.description": "",
            "User.userid": "",
            "User.username": "",
        }
        for field in self.user_fields:
            userInfo["User.%s" % field] = ""

        if tok.LinOtpUserid:
            # userInfo["User.description"]    = u'/:no user info:/'
            userInfo["User.userid"] = "/:no user info:/"
            userInfo["User.username"] = "/:no user info:/"

            uInfo = None

            try:
                uInfo = getUserInfo(
                    tok.LinOtpUserid,
                    tok.LinOtpIdResolver,
                    tok.LinOtpIdResClass,
                )

            except NoResolverFound:
                log.error("no user info found!")

            if uInfo is not None and len(uInfo) > 0:
                if "description" in uInfo:
                    description = uInfo.get("description")
                    userInfo["User.description"] = description

                if "userid" in uInfo:
                    userid = uInfo.get("userid")
                    userInfo["User.userid"] = userid

                if "username" in uInfo:
                    username = uInfo.get("username")
                    userInfo["User.username"] = username

                for field in self.user_fields:
                    fieldvalue = uInfo.get(field, "")
                    userInfo["User.%s" % field] = fieldvalue

        return (userInfo, uInfo)

    def __next__(self):
        tok = next(self.it)
        desc = tok.get_vars(save=True)
        """ add userinfo to token description """
        userInfo = {}
        try:
            (userInfo, _ret) = self.getUserDetail(tok)
        except Exception as exx:
            log.error("failed to get user detail %r", exx)
        desc.update(userInfo)

        return desc

    def __iter__(self):
        return self


# eof #########################################################################
