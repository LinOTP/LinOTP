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
#    You should have receive
# d a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#


"""
reporting controller - interfaces for Reporting
"""
import logging

from datetime import datetime

from flask import Response, stream_with_context, g, current_app
from werkzeug.datastructures import Headers

from linotp.flap import request, response
from linotp.controllers.base import BaseController
from linotp.lib.context import request_context

from linotp.lib.policy import (checkAuthorisation,
                               PolicyException,
                               getAdminPolicies)

from linotp.lib.realm import match_realms

from linotp.lib.reply import (sendResult,
                              sendError,
                              sendResultIterator,
                              sendCSVIterator)
from linotp.lib.reporting import ReportingIterator
from linotp.lib.reporting import get_max
from linotp.lib.reporting import delete
from linotp.lib.user import (getUserFromRequest, )
from linotp.lib.util import check_session
from linotp.lib.util import get_client

from linotp.model import db

log = logging.getLogger(__name__)


class ReportingController(BaseController):
    """
    reporting
    """

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context['action']

        try:

            g.audit['success'] = False

            g.audit['client'] = get_client(request)

            # Session handling
            check_session(request)

            checkAuthorisation(scope='reporting.access', method=action)

            return

        except Exception as exception:
            log.exception(exception)
            db.session.rollback()
            return sendError(response, exception, context='before')


    @staticmethod
    def __after__(response):
        '''
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        '''

        try:
            g.audit['administrator'] = getUserFromRequest(request).get('login')

            current_app.audit_obj.log(g.audit)
            db.session.commit()  # FIXME: may not be needed
            return response

        except Exception as exception:
            log.exception(exception)
            db.session.rollback()
            return sendError(response, exception, context='after')

    def maximum(self):
        """
        method:
            reporting/maximum

        description:
            return the maximum of tokens in a given realm with given status

        arguments:
            * realms - required: takes realms, only the reporting entries for
                this realms will be displayed
            * status - optional: (default is 'active')
                takes assigned/unassigned/active/ etc.
                and shows max of lines in database with this characteristic

        returns:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        exception:
            if an error occurs an exception is serialized and returned

        :return:
        """
        result = {}
        try:
            request_realms = self.request_params.get('realms', '').split(',')
            status = self.request_params.get('status', ['total'])
            if status != ['total']:
                status = status.split(',')

            realm_whitelist = []
            policies = getAdminPolicies('maximum', scope='reporting.access')

            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = list(request_context['Realms'].keys())

            realms = match_realms(request_realms, realm_whitelist)

            for realm in realms:
                result[realm] = {}
                for stat in status:
                    result[realm][stat] = get_max(realm, stat)

            return sendResult(response, result)

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            db.session.rollback()
            return sendError(response, str(policy_exception), 1)

        except Exception as exc:
            log.exception(exc)
            db.session.rollback()
            return sendError(response, exc)

    def delete_all(self):
        """
        method:
            reporting/delete_all

        description:
            delete entries from the reporting database table

        arguments:
        * realms - optional: takes realms, only the reporting entries
                from this realm are dedleted
        * status - optional: filters reporting entries by status
                like 'assigned' or 'inactive'

        returns: dict in which value is the number of deleted rows

        exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            request_realms = self.request_params.get('realms', '').split(',')
            status = self.request_params.get('status', ['total'])
            if status != ['total']:
                status = status.split(',')

            realm_whitelist = []
            policies = getAdminPolicies('delete_all', scope='reporting.access')

            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = list(request_context['Realms'].keys())

            realms = match_realms(request_realms, realm_whitelist)

            if '*' in status:
                status.remove('*')
                status.extend(['active', 'inactive', 'assigned', 'unassigned',
                               'active&assigned', 'active&unassigned',
                               'inactive&assigned', 'inactive&unassigned',
                               'total'])

            result = delete(realms=realms, status=status)
            db.session.commit()
            return sendResult(response, result)

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            db.session.rollback()
            return sendError(response, str(policy_exception), 1)

        except Exception as exc:
            log.exception(exc)
            db.session.rollback()
            return sendError(response, exc)

    def delete_before(self):
        """
        method:
            reporting/delete_before

        description:
            delete all entries from reporting database with respect to the
            arguments
            date must be given in format: 'yyyy-mm-dd'

        arguments:
        * date - optional: only delete entries which are older than date;
                date must be given in format 'yyyy-mm-dd'
                if no date is given, all entries get deleted
        * realms - optional: takes realms, only the reporting entries
                from this realm are dedleted
        * status - optional: filters reporting entries by status
                like 'assigned' or 'inactive'

        returns: dict in which value is the number of deleted rows

        exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            request_realms = self.request_params.get('realms', '').split(',')
            status = self.request_params.get('status', ['total'])
            if status != ['total']:
                status = status.split(',')

            border_day = self.request_params.get('date')

            # this may throw ValueError if date is in wrong format
            datetime.strptime(border_day, "%Y-%m-%d")

            realm_whitelist = []
            policies = getAdminPolicies('delete_before', scope='reporting')

            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = list(request_context['Realms'].keys())

            realms = match_realms(request_realms, realm_whitelist)

            result = delete(date=border_day, realms=realms, status=status)
            db.session.commit()
            return sendResult(response, result)

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            db.session.rollback()
            return sendError(response, str(policy_exception), 1)

        except ValueError as value_error:
            log.exception(value_error)
            db.session.rollback()
            return sendError(response, str(value_error), 1)

        except Exception as exc:
            log.exception(exc)
            db.session.rollback()
            return sendError(response, exc)

    def show(self):
        """
        method:
            reporting/show

        description:
            show entries from the reporting database table

        arguments:
        * date - optional: only show entries which are newer than date;
                date must be given in format 'yyyy-mm-dd'
                if no date is given, all entries are shown
        * realms - optional: takes realms, only the reporting entries
                from this realm are shown
        * status - optional: filters reporting entries by status
                like 'assigned' or 'inactive'
        * sortby  - optional: sort the output by column
        * sortdir - optional: asc/desc
        * page    - optional: reqeuest a certain page
        * pagesize - optional: limit the number of returned tokens
        * outform - optional: if set to "csv", the output will be a .csv file

        returns: a json result with:
            { "head": [],
            "data": [ [row1]
            , [row2]
            , [row3] .. ]
            }
        in case of csv:
        first line: header of columns
        other lines: column values


        exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            param = self.request_params
            page = param.get('page')
            sort = param.get('sortby')
            sortdir = param.get('sortdir')
            psize = param.get('pagesize')
            output_format = param.get('outform', 'json')
            request_realms = param.get('realms', '').split(',')
            status = param.get('status', [])
            border_day = param.get('date')

            if border_day:
                # this may throw ValueError if date is in wrong format
                datetime.strptime(border_day, "%Y-%m-%d")

            realm_whitelist = []
            policies = getAdminPolicies('show', scope='reporting.access')

            if policies['active'] and policies['realms']:
                realm_whitelist = policies.get('realms')

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or '*' in realm_whitelist:
                realm_whitelist = list(request_context['Realms'].keys())

            realms = match_realms(request_realms, realm_whitelist)

            reports = ReportingIterator(realms=realms, status=status, date=None,
                                        page=page, psize=psize, sort=sort,
                                        sortdir=sortdir)
            info = reports.getResultSetInfo()

            g.audit['success'] = True
            db.session.commit()

            if output_format == 'csv':
                headers = Headers()
                headers.add('Content-Disposition', 'attachment',
                            filename='linotp-reports.csv')
                return Response(
                    stream_with_context(
                        sendCSVIterator(reports.iterate_reports())),
                    mimetype='text/csv', headers=headers)
            else:
                return Response(
                    stream_with_context(
                        sendResultIterator(reports.iterate_reports(),
                                           opt=info)),
                    mimetype='application/json')

        except PolicyException as policy_exception:
            log.exception(policy_exception)
            db.session.rollback()
            return sendError(response, str(policy_exception), 1)

        except ValueError as value_error:
            log.exception(value_error)
            db.session.rollback()
            return sendError(response, str(value_error), 1)

        except Exception as exc:
            log.exception(exc)
            db.session.rollback()
            return sendError(response, exc)
