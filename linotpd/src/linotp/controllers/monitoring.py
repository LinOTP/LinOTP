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
monitoring controller - interfaces to monitor LinOTP
"""

import logging

from pylons import request, response, config, tmpl_context as c

from linotp.lib.base import BaseController
from linotp.lib.error import HSMException

from linotp.lib.util import check_session
from linotp.lib.util import get_client
from linotp.lib.user import (getUserFromRequest, )


from linotp.lib.realm import match_realms

from linotp.lib.reply import (sendResult,
                              sendError)
from linotp.model.meta import Session

from linotp.lib.policy import PolicyException

from linotp.lib.policy import checkAuthorisation
from linotp.lib.policy import getAdminPolicies


from linotp.lib.support import InvalidLicenseException, \
                               getSupportLicenseInfo, verifyLicenseInfo

from linotp.lib.monitoring import MonitorHandler

from linotp.lib.context import request_context

audit = config.get('audit')

log = logging.getLogger(__name__)


class MonitoringController(BaseController):
    """
    monitoring
    """

    def __before__(self, action, **params):
        """
        """
        try:

            c.audit = request_context['audit']
            c.audit['success'] = False

            c.audit['client'] = get_client(request)

            # Session handling
            check_session(request)

            request_context['Audit'] = audit
            checkAuthorisation(scope='monitoring', method=action)

            return request

        except Exception as exception:
            log.exception(exception)
            Session.rollback()
            Session.close()
            return sendError(response, exception, context='before')


    def __after__(self, action):
        """
        """
        params = {}
        try:
            params.update(request.params)
            c.audit['administrator'] = getUserFromRequest(request).get('login')

            audit.log(c.audit)
            Session.commit()
            return request

        except Exception as exception:
            log.exception(exception)
            Session.rollback()
            return sendError(response, exception, context='after')

        finally:
            Session.close()

    def tokens(self):
        """
        method:
            monitoring/tokens

        description:

            Displays the number of tokens (with status) per realm
            (one token might be in multiple realms).
            The Summary gives the sum of all tokens in all given realms and
            might be smaller than the summ of all tokens
            as tokens which have two realms are only counted once!

        arguments:
            * status - optional: takes assigned or unassigned, give the number
                of tokens with this characteristic

            * realms - optional: takes realms, only the number of tokens in
                these realms will be displayed

        returns:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        exception:
            if an error occurs an exception is serialized and returned
        """
        result = {}
        try:
            param = request.params

            status = param.get('status', ['total'])
            if status != ['total']:
                status = status.split(',')
                status.append('total')
            request_realms = param.get('realms', '').split(',')

            monit_handler = MonitorHandler()
            realm_whitelist = []

            policies = getAdminPolicies('tokens', scope='monitoring')

            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = request_context['Realms'].keys()

            realms = match_realms(request_realms, realm_whitelist)

            realm_info = {}
            for a_realm in realms:
                token_count = monit_handler.token_count([a_realm],
                                                        status)
                realm_info[a_realm] = token_count

            result['Summary'] = monit_handler.token_count(realms, status)
            result['Realms'] = realm_info

            Session.commit()
            return sendResult(response, result)

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            Session.rollback()
            return sendError(response, unicode(policy_exception), 1)

        except Exception as exc:
            log.exception(exc)
            Session.rollback()
            return sendError(response, exc)

        finally:
            Session.close()

    def config(self):
        """
        check if Config- Database exists

        touches DB and checks if date of last read is new
        :return:
            a json result with:
            { "head": [],
            "value": {"sync": "True"}
            }

        exception:
            if an error occurs an exception is serialized and returned
        """
        result = {}
        try:

            monit_handler = MonitorHandler()
            result = monit_handler.get_sync_status()

            # useful counts:
            counts = monit_handler.get_config_info()

            result.update(counts)

            ldap = 13 * result['ldapresolver']
            sql = 12 * result['sqlresolver']
            policies = 7 * result['policies']
            realms = result['realms']
            passwd = result['passwdresolver']
            total = result['total']

            result['netto'] = total - ldap - sql - passwd - policies - realms

            return sendResult(response, result)

        except Exception as exception:
            log.exception(exception)
            return sendError(response, exception)

        finally:
            Session.close()

    def storageEncryption(self):
        """
        check if hsm/enckey encrypts value before storing it to config db
        :return: true if a new value gets encryptet before beeing stored in db
        """
        try:
            if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
                raise HSMException('no hsm defined in execution context!')

            hsm = c.hsm.get('obj')
            if hsm is None or hsm.isReady() is False:
                raise HSMException('hsm not ready!')

            hsm_class = str(type(hsm))
            enc_type = hsm_class.split('.')[-1]
            enc_type = enc_type.strip("'>")
            enc_name = hsm.name
            res = {'cryptmodul_type': enc_type, 'cryptmodul_name': enc_name}

            monit_handler = MonitorHandler()
            res['encryption'] = monit_handler.check_encryption()

            return sendResult(response, res, 1)

        except Exception as exception:
            log.exception(exception)
            return sendError(response, exception)

        finally:
            Session.close()

    def license(self):
        """
        license
        return the support status, which is community support by default
        or the support subscription info, which could be the old license
        :return: json result with license info
        """
        res = {}
        try:
            try:
                license_info, license_sig = getSupportLicenseInfo()
            except InvalidLicenseException as err:
                if err.type != 'UNLICENSED':
                    raise err
                opt = {'valid': False,
                       'message': "%r" % err
                       }
                return sendResult(response, {}, 1, opt=opt)

            # Add Extra info
            # if needed; use details = None ... for no details!)...
            license_ok, license_msg = verifyLicenseInfo(license_info,
                                                        license_sig)
            if not license_ok:
                res = {'valid': license_ok,
                           'message': license_msg
                           }
            else:
                details = {'valid': license_ok}

                res['token-num'] = int(license_info.get('token-num', 0))

                # get all active tokens from all realms (including norealm)
                monit_handler = MonitorHandler()
                active_tokencount = monit_handler.get_active_tokencount()
                res['token-active'] = active_tokencount

                res['token-left'] = res['token-num'] - active_tokencount

            return sendResult(response, res, 1)

        except Exception as exception:
            log.exception(exception)
            return sendError(response, exception)

        finally:
            Session.close()

    def userinfo(self):
        """
        method:
            monitoring/userinfo

        description:
            for each realm, display the resolvers and the number of users
            per resolver

        arguments:
            * realms - optional: takes a realm, only information on this realm
                will be displayed

        returns:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        """
        result = {}
        try:
            param = request.params
            request_realms = param.get('realms', '').split(',')

            monit_handler = MonitorHandler()

            policies = getAdminPolicies('userinfo', scope='monitoring')

            realm_whitelist = []
            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = request_context['Realms'].keys()

            realms = match_realms(request_realms, realm_whitelist)

            if '/:no realm:/' in realms:
                realms.remove('/:no realm:/')

            realm_info = {}
            for a_realm in realms:
                realm_info[a_realm] = monit_handler.resolverinfo(a_realm)

            result['Realms'] = realm_info

            Session.commit()
            return sendResult(response, result)

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            Session.rollback()
            return sendError(response, unicode(policy_exception), 1)

        except Exception as exc:
            log.exception(exc)
            Session.rollback()
            return sendError(response, exc)

        finally:
            Session.close()

    def activeUsers(self):
        """
        method:
            monitoring/activeUsers

        description:
            for each realm, display the resolvers and
            the number of users which have at least one assigned active token
            per resolver
            the 'total' gives the number of all users, which are in an allowed
            realm and own an active token
            users are conted per resolver (not per realm), so if resolver is in
            multiple realms and one user ons tokens in 2 realms, the user will
            be counted only once

        arguments:
            * realms - optional: takes realms, only information on these realms
                will be displayed
        """
        result = {}
        try:
            param = request.params
            request_realms = param.get('realms', '').split(',')

            monit_handl = MonitorHandler()

            policies = getAdminPolicies('activeUsers', scope='monitoring')

            realm_whitelist = []
            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = request_context['Realms'].keys()

            realms = match_realms(request_realms, realm_whitelist)

            realm_info = {}
            for a_realm in realms:
                realm_info[a_realm] = monit_handl.active_users_per_realm(a_realm)

            result['Realms'] = realm_info
            result['total'] = monit_handl.active_users_total(realms)

            return sendResult(response, result)

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            Session.rollback()
            return sendError(response, unicode(policy_exception), 1)

        except Exception as exc:
            log.exception(exc)
            Session.rollback()
            return sendError(response, exc)

        finally:
            Session.close()




