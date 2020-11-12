# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
helpdesk controller - interfaces to administrate LinOTP as helpdesk
"""
import os
import logging

from flask import current_app, g

from linotp.flap import (
    config, request, response)


from linotp.controllers.base import BaseController, SessionCookieMixin

from linotp.lib.reply import sendResult
from linotp.lib.reply import sendError

from linotp.lib.user import User

from linotp.lib.user import getUserFromParam
from linotp.lib.user import getUserFromRequest

from linotp.lib.policy import checkPolicyPre
from linotp.lib.policy import checkPolicyPost
from linotp.lib.policy import PolicyException

from linotp.lib.policy import getAdminPolicies
from linotp.lib.policy import createRandomPin

from linotp.tokens import tokenclass_registry
from linotp.lib.token import get_token_owner
from linotp.lib.token import TokenHandler
from linotp.lib.token import getTokens4UserOrSerial

from linotp.lib.tokeniterator import TokenIterator

from linotp.lib.util import get_client

from linotp.lib.error import ParameterError
from linotp.lib.error import TokenAdminError

from linotp.lib.context import request_context
from linotp.lib.realm import getRealms

from linotp.lib.user import getUserList

from linotp.lib.util import unicode_compare, SESSION_KEY_LENGTH
from linotp.lib.util import check_session

from linotp.provider.notification import notify_user

from linotp.lib.audit.base import get_token_num_info

from linotp.lib.realm import get_realms_from_params

from linotp.model import db

log = logging.getLogger(__name__)


class HelpdeskController(BaseController, SessionCookieMixin):

    '''
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The HelpdeskController is used for administrative tasks like adding tokens
    to LinOTP, assigning tokens or revoking tokens.
    The functions of the HelpdeskController are invoked like this

        https://server/api/helpdesk/<functionname>

    The functions are described below in more detail.
    '''

    session_cookie_name = "helpdesk_session"  # for `SessionCookieMixin`

    def __before__(self,  **params):
        '''
        '''

        action = request_context['action']

        try:

            g.audit['success'] = False
            g.audit['client'] = get_client(request)

            # Session handling
            if action not in ['getsession', 'dropsession']:
                check_session(request, scope='helpdesk')

        except Exception as exx:
            log.exception("[__before__::%r] exception", action)

            db.session.rollback()
            return sendError(None, exx, context='before')

    @staticmethod
    def __after__(response):
        '''
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        '''

        try:
            g.audit['administrator'] = getUserFromRequest(request).get("login")
            g.audit['serial'] = request.params.get('serial')

            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as e:
            log.exception(
                "[__after__] unable to create a session cookie: %r" % e)
            db.session.rollback()
            return sendError(response, e, context='after')

    def tokens(self):
        '''
        This function is used to fill the flexigrid.
        Unlike the complex /admin/show function, it only returns a
        simple array of the tokens.
        '''
        param = self.request_params

        try:
            page = param.get("page", 1)
            qfilter = param.get("query")
            qtype = param.get("qtype", 'all')
            sort = param.get("sortname", )
            direction = param.get("sortorder", "desc")
            psize = param.get("rp", 20)

            filter_all = None
            filter_realm = None
            user = User()

            if qtype == "loginname":

                # we take by default the given expression as a loginname,
                # especially if it contains a "*" wildcard.
                # it only might be more, a user and a realm, if there
                # is an '@' sign in the loginname and the part after the
                # last '@' sign is matching an existing realm

                user = User(login=qfilter)

                if "*" not in qfilter and "@" in qfilter:

                    login, _, realm = qfilter.rpartition("@")

                    if realm.lower() in getRealms():
                        user = User(login, realm)
                        if not user.exists():
                            user = User(login=qfilter)

            elif qtype == "all":
                filter_all = qfilter

            elif qtype == "realm":
                filter_realm = qfilter

            # check admin authorization
            res = checkPolicyPre('admin', 'show', param, user=user)

            filterRealm = res['realms']
            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            pol = getAdminPolicies("show")

            # If there are no admin policies, we are allowed to see all realms
            if not pol['active']:
                filterRealm = ["*"]

            # check if we only want to see ONE realm or see all realms
            # we are allowerd to see.
            if filter_realm:
                if filter_realm in filterRealm or '*' in filterRealm:
                    filterRealm = [filter_realm]

            tokenArray = TokenIterator(
                user, None, page, psize, filter_all, sort,
                direction, filterRealm=filterRealm)

            resultset = tokenArray.getResultSetInfo()
            # If we have chosen a page to big!
            lines = []
            for tok in tokenArray:
                lines.append({
                    'id': tok['LinOtp.TokenSerialnumber'],
                    'cell': [
                        tok['LinOtp.TokenSerialnumber'],
                        tok['LinOtp.Isactive'],
                        tok['User.username'],
                        tok['LinOtp.RealmNames'],
                        tok['LinOtp.TokenType'],
                        tok['LinOtp.FailCount'],
                        tok['LinOtp.TokenDesc'],
                        tok['LinOtp.MaxFail'],
                        tok['LinOtp.OtpLen'],
                        tok['LinOtp.CountWindow'],
                        tok['LinOtp.SyncWindow'],
                        tok['LinOtp.Userid'],
                        tok['LinOtp.IdResClass'].split('.')[-1],
                    ]
                })

            # We need to return 'page', 'total', 'rows'
            res = {
                "page": int(page),
                "total": resultset['tokens'],
                "rows": lines
            }

            g.audit['success'] = True
            db.session.commit()
            return sendResult(None, res)

        except PolicyException as pex:
            log.exception("Error during checking policies")
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:
            log.exception("tokens lookup failed!")
            db.session.rollback()
            return sendError(response, exx)

    def users(self):
        '''
        This function is used to fill the flexigrid.
        Unlike the complex /admin/userlist function, it only returns a
        simple array of the tokens.
        '''
        param = self.request_params

        try:

            page = param.get("page", 1)
            qfilter = param.get("query", '*') or '*'
            qtype = param.get("qtype", 'username')
            sort = param.get("sortname", 'username')
            direction = param.get("sortorder", 'asc')
            psize = param.get("rp", 20)

            user = getUserFromParam(param)

            realms = get_realms_from_params(
                param, getAdminPolicies('userlist', scope='admin'))

            uniqueUsers = {}
            for realm in realms:

                # ---------------------------------------------------------- --

                # check admin authorization: checkPolicyPre('admin',...

                # admin policies are special as they are acl which define
                # - for user (policy entry)
                # - the actions (policy entry)
                # - in the realm (policy entry)
                # is allowed. while the user.login is not evaluated, the
                # user.realm is.
                #
                # the admin policies are acls and are defined in contradiction
                # to the other policy scopes where actions are either defiend
                # for user or realm!!

                # so we have to check for every user.realm

                if isinstance(user, User):
                    user.realm = realm

                checkPolicyPre('admin', 'userlist', param=param, user=user)

                users_list = getUserList(
                    {qtype: qfilter, 'realm': realm}, user)

                # now create a unique list of users with the unique key of
                # userid + useridresolver

                for u in users_list:
                    pkey = u['userid'] + ':' + u['useridresolver']
                    user_realms = uniqueUsers.get(pkey, {}).get('realms', [])
                    user_realms.append(realm)
                    u['realms'] = user_realms
                    uniqueUsers[pkey] = u

            userNum = len(uniqueUsers)

            lines = []
            for u in uniqueUsers.values():
                # shorten the useridresolver, to get a better display value
                resolver_display = ""
                if "useridresolver" in u:
                    if len(u['useridresolver'].split(".")) > 3:
                        resolver_display = u['useridresolver'].split(
                            ".")[3] + " (" + u['useridresolver'].split(".")[1] + ")"
                    else:
                        resolver_display = u['useridresolver']
                lines.append(
                    {'id': u['username'],
                        'cell': [
                            u.get('username', ''),
                            resolver_display,
                            u.get('surname', ''),
                            u.get('givenname', ''),
                            u.get('email', ''),
                            u.get('mobile', ''),
                            u.get('phone', ''),
                            u.get('userid', ''),
                            u.get('realms', ''),
                    ]
                    }
                )

            # sorting
            reverse = False
            sortnames = {
                'username': 0,
                'useridresolver': 1,
                'surname': 2,
                'givenname': 3,
                'email': 4,
                'mobile': 5,
                'phone': 6,
                'userid': 7
            }
            if direction == "desc":
                reverse = True

            lines = sorted(lines,
                           key=lambda user: user['cell'][sortnames[sort]],
                           reverse=reverse
                           )

            # end: sorting

            # reducing the page
            if page and psize:
                page = int(page)
                psize = int(psize)
                start = psize * (page - 1)
                end = start + psize
                lines = lines[start:end]

            # We need to return 'page', 'total', 'rows'
            res = {
                "page": int(page),
                "total": userNum,
                "rows": lines
            }

            g.audit['success'] = True

            db.session.commit()
            return sendResult(None, res)

        except PolicyException as pe:
            log.exception(
                "[userview_flexi] Error during checking policies: %r" % pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.exception("[userview_flexi] failed: %r" % e)
            db.session.rollback()
            return sendError(response, e)

    def enroll(self):
        """
        method:
            api/helpdesk/enroll

        description:
            method to enroll a token as helpdesk

        arguments:
            * type: the token type, currently only 'email'
            * user: the new token owner
            * realm: (optional) the realm the user belongs to - used to identify the user

        returns:
            success as boolean

        """

        ret = False
        response_detail = {}

        params = self.request_params

        try:

            if 'user' not in params:
                raise ParameterError('missing parameter: user!')

            if 'type' not in params:
                raise ParameterError('missing parameter: type!')

            # --------------------------------------------------------------- --

            # determine token class

            token_cls_alias = params.get("type")
            lower_alias = token_cls_alias.lower()

            if lower_alias not in tokenclass_registry:
                raise TokenAdminError('admin/init failed: unknown token '
                                      'type %r' % token_cls_alias, id=1610)

            token_cls = tokenclass_registry.get(lower_alias)

            # --------------------------------------------------------------- --

            # call the token class hook in order to enrich/overwrite the
            # parameters

            helper_params = token_cls.get_helper_params_pre(params)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            # fetch user from parameters.

            user = getUserFromParam(params)

            # --------------------------------------------------------------- --

            # create a new pin according to the policies

            if 'pin' not in params:
                params['pin'] = createRandomPin(user, min_pin_length=6)

            # --------------------------------------------------------------- --

            if 'otpkey' not in params:
                params['genkey'] = '1'

            # --------------------------------------------------------------- --

            # check admin authorization

            res = checkPolicyPre('admin', 'init', params, user=user)

            # --------------------------------------------------------------- --

            helper_params = token_cls.get_helper_params_post(params, user=user)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            # create new serial

            th = TokenHandler()

            serial = th.genSerial(token_cls_alias)
            params['serial'] = serial

            log.info("[init] initialize token. user: %s, serial: %s"
                     % (user.login, serial))

            # --------------------------------------------------------------- --

            # scope_extension: we are in scope helpdesk
            # this is eg required to notify the emailtoken to use the
            # email from user if none is given as param

            params['::scope::'] = {
                'helpdesk': True,
                'user': user
            }

            (ret, token) = th.initToken(params, user)

            # --------------------------------------------------------------- --

            # different token types return different information on
            # initialization (e.g. otpkey, pairing_url, etc)

            initDetail = token.getInitDetail(params, user)
            response_detail.update(initDetail)

            # --------------------------------------------------------------- --

            # prepare data for audit

            if token is not None and ret is True:
                g.audit['serial'] = token.getSerial()
                g.audit['token_type'] = token.type

            g.audit['success'] = ret
            g.audit['user'] = user.login
            g.audit['realm'] = user.realm

            g.audit['action_detail'] += get_token_num_info()

            res = checkPolicyPost('admin', 'init', params, user=user)
            pin = res.get('new_pin', params['pin'])

            message = ("A new ${tokentype} token (${serial}) "
                       "with pin '${Pin}' "
                       "for ${givenname} ${surname} has been enrolled.")
            info = {
                'message': message,
                'Subject': 'New %s token enrolled' % token.type,
                'Pin': pin,
                'tokentype': token.type
            }
            info.update(response_detail)

            notify_user(user, 'enrollment', info, required=True)

            g.audit['action_detail'] += get_token_num_info()

            g.audit['success'] = ret

            return sendResult(None, ret)

        except PolicyException as pex:
            log.exception("Policy Exception while enrolling token")
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:
            log.exception("Exception while enrolling token")
            db.session.rollback()
            return sendError(response, exx, 1)


########################################################


    def setPin(self):
        """
        method:
            api/helpdesk/setPin

        description:
            This function sets the PIN of the token

        arguments:
            * serial     - required
            * pin        - optional - uses random pin instead

        returns:
            an array with the list of affected serial numbers

        """
        res = {}

        try:
            params = self.request_params

            serial = params.get("serial")
            if not serial:
                raise ParameterError("Missing parameter: 'serial'")

            tokens = getTokens4UserOrSerial(serial=serial)

            result = []

            for token in tokens:
                owner = get_token_owner(token)
                current_serial = token.getSerial()

                pin = params.get(
                    'pin', createRandomPin(owner, min_pin_length=6))

                # as the parameter pin in the params is evaluated by
                # the checkPolicyPre and checkPolicyPost we need to put the
                # parameter pin and current_serial into the params
                params['pin'] = pin
                params['serial'] = current_serial

                # set pin is done by the admin/set with the parameter pin
                checkPolicyPre(
                    'admin', method='set', param=params, user=owner)

                token.setPin(pin)

                # while in the pre checks for method='set' the post checks
                # for 'setPin' which is used to determin if a new pin has to
                # be generated

                res = checkPolicyPost(
                    'admin', 'setPin', param=params, user=owner)
                pin = res.get('new_pin', pin)

                info = {
                    'message': ('A new pin ${Pin} has been set for your '
                                'token: ${serial}'),
                    'Subject': 'new pin set for token ${serial}',
                    'Pin': pin,
                    'serial': current_serial,
                }

                notify_user(owner, 'setPin', info, required=True)

                result.append(serial)

            g.audit['success'] = True
            g.audit['info'] = result

            db.session.commit()
            return sendResult(None, result)

        except PolicyException as pex:
            log.exception('[setPin] policy failed %r')
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:
            log.exception('[setPin] error while setting pin')
            db.session.rollback()
            return sendError(response, exx, 0)
