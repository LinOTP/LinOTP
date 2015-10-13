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
monitoring controller - interfaces to monitor LinOTP
"""

import logging

from pylons import request, response, config, tmpl_context as c
from pylons.i18n.translation import _

from linotp.lib.base import BaseController
from linotp.lib.config import getLinotpConfig

from linotp.lib.realm import getRealms

from linotp.lib.util import check_session
from linotp.lib.util import get_client
from linotp.lib.user import (getUserFromRequest, )

from linotp.lib.reply import (sendResult,
                              sendError)
from linotp.model.meta import Session

from linotp.lib.policy import (PolicyException, getPolicies)

from linotp.lib.support import InvalidLicenseException, \
                               getSupportLicenseInfo, verifyLicenseInfo

from linotp.lib.monitoring import MonitorHandler

audit = config.get('audit')

log = logging.getLogger(__name__)


class MonitoringController(BaseController):
    """
    monitoring
    """
    context = {}

    def __before__(self, action, **params):
        """
        """
        try:
            log.debug('[__before__::%r] %r', action, params)

            audit.initialize()
            c.audit['success'] = False
            c.audit['client'] = get_client()
            
            # Session handling
            check_session()

            # TODO call methode to build context
            # First we load the Config
            l_config = getLinotpConfig()
            self.context['user'] = getUserFromRequest(request)
            self.context['policies'] = getPolicies(l_config)
            # TODO add client to context (for policies)
            # this calls getLinotpConfig() again!!
            self.context['all_realms'] = getRealms()

            return request

        except Exception as exception:
            log.exception(exception)
            Session.rollback()
            Session.close()
            return sendError(response, exception, context='before')

        finally:
            log.debug('[__before__::%r] done', action)

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
            log.debug('[__after__] done')

    def tokens(self):
        """
        method:
            monitoring/tokens

        description:
            displays the number of the available tokens per realm

        arguments:
            * status - optional: takes assigned or unassigned, give the number
                of tokens with this characteristic
            * realms - optional: takes a realm, only the number of tokens in
                this realm will be displayed

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
            status = param.get('status')
            # do NOT initialize status  with ''
            if status:
                status = status.split(',')
            request_realms = param.get('realms', '').split(',')

            monit_handler = MonitorHandler(context=self.context)
            realm_whitelist = monit_handler.get_allowed_realms()

            # by default we show all allowed realms
            realms = realm_whitelist

            # support for empty realms or no realms by realm = *
            if '*' in request_realms:
                realms = realm_whitelist
                realms.append('/:no realm:/')
            # other cases, we iterate through the realm list
            elif len(request_realms) > 0 and not (request_realms == ['']):
                realms = []
                invalid_realms = []
                for search_realm in request_realms:
                    search_realm = search_realm.strip()
                    if search_realm in realm_whitelist:
                        realms.append(search_realm)
                    elif search_realm == '/:no realm:/':
                        realms.append(search_realm)
                    else:
                        invalid_realms.append(search_realm)
                if not realms and invalid_realms:
                    raise PolicyException(_('You do not have the rights to '
                                            'monitor these realms: %r. '
                                            'Check the policies!')
                                          % invalid_realms)

            # if there was realm or no argument given:
            totals = {}
            realm_info = {}
            for a_realm in realms:
                realm_dict = {}

                token_count = monit_handler.token_per_realm_count(a_realm,
                                                                  status)
                for key in token_count.keys():
                    realm_dict[key] = token_count[key]
                    totals[key] = totals.get(key, 0) + token_count[key]

                realm_info[a_realm] = realm_dict

            result[_('Summary')] = totals
            result[_('Realms')] = realm_info

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
            log.debug('[tokens] done')

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
            monit_handler = MonitorHandler(context=self.context)

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
            log.debug('[__after__] done')

    def license(self):
        """
        return
        return the support status, which is community support by default
        or the support subscription info, which could be the old license
        """
        res = {}
        try:
            try:
                license_info, license_sig = getSupportLicenseInfo(validate=False)
            except InvalidLicenseException as err:
                if err.type <> 'UNLICENSED':
                    raise # Certificate "formating" errors are not ignored!
                return sendResult(response, {}, 1, 
                                  opt={ 'valid': False, 'message': str(err) })

            ### Add Extra infos (if needed; use details = None ... for no details!)...
            license_chk, license_msg = verifyLicenseInfo(license_info, license_sig)
            if license_chk:
                details = { 'valid': license_chk }
            else:
                details = { 'valid': license_chk, 'message': license_msg }
            ###
			
            res['token-num'] = license_info.get('token-num', 0)

            # get all active tokens from all realms (including norealm)
            monit_handler = MonitorHandler(context=self.context)
            active_tokencount = monit_handler.get_active_tokencount()
            res['token-active'] = str(active_tokencount)

            res['token-left'] = str(int(res['token-num']) - active_tokencount)

            return sendResult(response, res, 1, opt=details)

        except Exception as exception:
            log.exception(exception)
            return sendError(response, exception)

        finally:
            Session.close()
            log.debug('[__after__] done')
