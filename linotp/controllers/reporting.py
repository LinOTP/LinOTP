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
#    You should have receive
# d a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


"""
reporting controller - interfaces for Reporting
"""

import logging
from datetime import datetime, timedelta

from flask import Response, current_app, g, stream_with_context
from werkzeug.datastructures import Headers

from linotp.controllers.base import BaseController, methods
from linotp.lib import deprecated_methods
from linotp.lib.context import request_context
from linotp.lib.policy import (
    PolicyException,
    checkAuthorisation,
    match_allowed_realms,
)
from linotp.lib.reply import (
    sendCSVIterator,
    sendError,
    sendResult,
    sendResultIterator,
)
from linotp.lib.reporting import (
    ReportingIterator,
    delete,
    get_last_token_count_before_date,
    get_max_token_count_in_period,
)
from linotp.lib.type_utils import convert_to_datetime
from linotp.lib.user import getUserFromRequest
from linotp.model import db

log = logging.getLogger(__name__)

TIME_FMTS = ["%Y-%m-%d"]


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

        action = request_context["action"]

        try:
            checkAuthorisation(scope="reporting.access", method=action)
        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        try:
            g.audit["administrator"] = getUserFromRequest()

            current_app.audit_obj.log(g.audit)
            db.session.commit()  # FIXME: may not be needed
            return response

        except Exception as exx:
            log.error("[__after__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @staticmethod
    def _match_allowed_realms(requested_realms: list[str]):
        """Returns a list of realm names the user is allowed to access for given scope.action.

        Args:
            requested_realms (List[str]): List of realms, the user wants to access.
                Use `["*"]` to match against all realms including "/:no realm:/".

        Returns:
            List[str]: List of realms the user is allowed to access for given action.
        """
        scope = "reporting.access"
        action = request_context["action"]
        return match_allowed_realms(scope, action, requested_realms)

    @deprecated_methods(["POST"])
    def maximum(self):
        """
        return the maximum of tokens in a given realm with given status

        :param realms: (required) takes realms, only the reporting
            entries for this realms will be displayed. If "realms" is
            omitted, all realms are evaluated, including /:no realm:/.

        :param status: (optional) (default is 'active')
                takes assigned/unassigned/active/ etc.
                and shows max of lines in database with this characteristic

        :return:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        try:
            # ------------------------------------------------------------- --
            start = datetime(year=1970, month=1, day=1)

            _now = datetime.utcnow()
            end = datetime(year=_now.year, month=_now.month, day=_now.day) + timedelta(
                days=1
            )
            # ------------------------------------------------------------- --

            request_realms = self.request_params.get("realms", "*").split(",")
            status = self.request_params.get("status", ["total"])
            status = status.split(",") if status != ["total"] else ["total"]

            realms = self._match_allowed_realms(request_realms)

            result = {
                realm: {
                    stat: get_max_token_count_in_period(
                        realm, status=stat, start=start, end=end
                    )
                    for stat in status
                }
                for realm in realms
            }
            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except Exception as exc:
            log.error(exc)
            db.session.rollback()
            return sendError(exc)

        finally:
            db.session.close()

    @deprecated_methods(["POST"])
    def period(self):
        """

        return the maximum of tokens in a given realm with given status
        for a given period

        :param realms: (required) takes realms, only the reporting
            entries for this realms will be displayed. If "realms" is
            omitted, all realms are evaluated, including /:no realm:/.

        :param status: (optional) (default is 'active')
                takes assigned/unassigned/active/ etc.
                and shows max of lines in database with this characteristic

        :param from: (optional) (default is 1970-1-1)
                    the start day for the reporting max lookup

        :param to: (optional) (default is tomorrow 0:0:0)
                    the end day for the reporting max lookup

        :return:
            a json result with:
            {
            "status": "true",
            "value": {
                realms: [ {}, {}],
                period: {
                    'from':
                    'to':
                }
            }
            with a realm entry {} as:
            {
            'realm': 'realmname',
            'tokencount': {
                'active': nn,

                }
            }

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        try:
            request_realms = self.request_params.get("realms", "*").split(",")
            status = self.request_params.get("status", ["total"])
            status = status.split(",") if status != ["total"] else ["total"]

            # ------------------------------------------------------------- --

            # handle start and stop
            # for backward compatibility start and stop are optional

            # if start is not given, we use the unix time start 1.1.1970

            start = datetime(year=1970, month=1, day=1)
            if "from" in self.request_params:
                start_str = self.request_params.get("from")
                start = convert_to_datetime(start_str, TIME_FMTS)

            # if end is not defined, we use tomorrow at 0:0:0

            _now = datetime.utcnow()
            end = datetime(year=_now.year, month=_now.month, day=_now.day) + timedelta(
                days=1
            )
            if "to" in self.request_params:
                end_str = self.request_params.get("to")
                end = convert_to_datetime(end_str, TIME_FMTS)

            # ------------------------------------------------------------- --

            realms = self._match_allowed_realms(request_realms)

            result = {
                "realms": [],
                "period": {"from": start.isoformat(), "to": end.isoformat()},
            }
            for realm in realms:
                result_realm = {"name": realm, "maxtokencount": {}}
                for stat in status:
                    # search for the max token in the period [start : end]
                    max_token_stat = get_max_token_count_in_period(
                        realm, status=stat, start=start, end=end
                    )

                    # if none is found (-1) we search for the last entry
                    # before the period start
                    if max_token_stat == -1:
                        max_token_stat = get_last_token_count_before_date(
                            realm, status=stat, before_date=start
                        )

                    result_realm["maxtokencount"][stat] = max_token_stat

                result["realms"].append(result_realm)

            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except Exception as exc:
            log.error(exc)
            db.session.rollback()
            return sendError(exc)

    @methods(["POST"])
    def delete_all(self):
        """
        method:
            reporting/delete_all

        description:
            delete entries from the reporting database table

        :param realms: takes realms, only the reporting entries from
            this realm are deleted. If "realms" is omitted, all realms
            are evaluated, including /:no realm:/.

        :param status: (optional) filters reporting entries by status like 'assigned' or 'inactive'

        returns: dict in which value is the number of deleted rows

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            request_realms = self.request_params.get("realms", "*").split(",")
            status = self.request_params.get("status", ["total"])
            if status != ["total"]:
                status = status.split(",")

            realms = self._match_allowed_realms(request_realms)

            if "*" in status:
                status.remove("*")
                status.extend(
                    [
                        "active",
                        "inactive",
                        "assigned",
                        "unassigned",
                        "active&assigned",
                        "active&unassigned",
                        "inactive&assigned",
                        "inactive&unassigned",
                        "total",
                    ]
                )

            result = delete(realms=realms, status=status)
            db.session.commit()
            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except Exception as exc:
            log.error(exc)
            db.session.rollback()
            return sendError(exc)

    @methods(["POST"])
    def delete_before(self):
        """

        delete all entries from reporting database with respect to the
        arguments

        .. note:: date must be given in format: 'yyyy-mm-dd'

        :param date: (optional) only delete entries which are older than date;
                date must be given in format 'yyyy-mm-dd' . if no date is given, all entries get deleted

        :param realms: (optional) takes realms, only the reporting
            entries from this realm are deleted. If "realms" is omitted,
            all realms are evaluated, including /:no realm:/.

        :param status: (optional) filters reporting entries by status
                like 'assigned' or 'inactive'

        :return: dict in which value is the number of deleted rows

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            request_realms = self.request_params.get("realms", "*").split(",")
            status = self.request_params.get("status", ["total"])
            if status != ["total"]:
                status = status.split(",")

            border_day = self.request_params.get("date")

            # this may throw ValueError if date is in wrong format
            datetime.strptime(border_day, "%Y-%m-%d")

            realms = self._match_allowed_realms(request_realms)

            result = delete(date=border_day, realms=realms, status=status)
            db.session.commit()
            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except ValueError as value_error:
            log.error(value_error)
            db.session.rollback()
            return sendError(value_error, 1)

        except Exception as exc:
            log.error(exc)
            db.session.rollback()
            return sendError(exc)

    @deprecated_methods(["POST"])
    def show(self):
        """
        show entries from the reporting database table


        :param date: (optional) only show entries which are newer than date;
                date must be given in format 'yyyy-mm-dd'
                if no date is given, all entries are shown

        :param realms: (optional) takes realms, only the reporting
            entries from this realm are shown. If "realms" is omitted,
            all realms are evaluated, including /:no realm:/.

        :param status: (optional) filters reporting entries by status
                like 'assigned' or 'inactive'

        :param sortby:  (optional) sort the output by column
        :param sortdir: (optional) asc/desc
        :param page:    (optional) request a certain page
        :param pagesize: (optional) limit the number of returned tokens
        :param outform: (optional) if set to "csv", the output will be a .csv file

        :return: a json result with:
            { "head": [],
            "data": [ [row1]
            , [row2]
            , [row3] .. ]
            }
        in case of csv:
        first line: header of columns
        other lines: column values

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            param = self.request_params
            page = param.get("page")
            sort = param.get("sortby")
            sortdir = param.get("sortdir")
            psize = param.get("pagesize")
            output_format = param.get("outform", "json")
            request_realms = param.get("realms", "*").split(",")
            status = param.get("status", [])

            start_day = None
            if "date" in param:
                start_day = convert_to_datetime(param.get("date"), TIME_FMTS)

            realms = self._match_allowed_realms(request_realms)

            reports = ReportingIterator(
                realms=realms,
                status=status,
                date=start_day,
                page=page,
                psize=psize,
                sort=sort,
                sortdir=sortdir,
            )
            info = reports.getResultSetInfo()

            g.audit["success"] = True
            db.session.commit()

            if output_format == "csv":
                headers = Headers()
                headers.add(
                    "Content-Disposition",
                    "attachment",
                    filename="linotp-reports.csv",
                )
                return Response(
                    stream_with_context(sendCSVIterator(reports.iterate_reports())),
                    mimetype="text/csv",
                    headers=headers,
                )
            else:
                return Response(
                    stream_with_context(
                        sendResultIterator(reports.iterate_reports(), opt=info)
                    ),
                    mimetype="application/json",
                )

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except ValueError as value_error:
            log.error(value_error)
            db.session.rollback()
            return sendError(value_error, 1)

        except Exception as exc:
            log.error(exc)
            db.session.rollback()
            return sendError(exc)
