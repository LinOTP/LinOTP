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
import json
import logging

from sqlalchemy import and_, func, or_

from linotp.lib.context import request_context
from linotp.lib.monitoring import MonitorHandler
from linotp.lib.policy import get_active_token_statuses_for_reporting
from linotp.model import db
from linotp.model.reporting import Reporting

STATI = [
    "total",
    "active",
    "inactive",
    "assigned",
    "unassigned",
    "active&assigned",
    "active&unassigned",
    "inactive&assigned",
    "inactive&unassigned",
]

log = logging.getLogger(__name__)


def token_reporting(event, tokenrealms):
    """
    log token events into reporting table

    :param event: the event that happened, e.g. init token, delete token
    :param tokenrealms: the realm on which the event happened
    :return: nothing
    """
    realms = tokenrealms
    if not tokenrealms or len(tokenrealms) == 0:
        realms = ["/:no realm:/"]
    elif not isinstance(tokenrealms, (list, tuple, set)):
        realms = [tokenrealms]

    for realm in realms:
        action = get_active_token_statuses_for_reporting(realm)
        mh = MonitorHandler()
        counters = mh.token_count(realm, action[:])
        for key, val in list(counters.items()):
            report = Reporting(event=event, realm=realm, parameter=key, count=val)
            try:
                db.session.add(report)
            except Exception as exce:
                log.error("Error during saving report. Exception was %r", exce)


def get_max_token_count_in_period(realm, start=None, end=None, status="active"):
    """Search for the maximum token count value in the reporing events
    in a period with the status and realm.

    :param realm: (required) the realm in which we are searching
    :param start: timestamp (default: 1.1.1970)
                  the reporting start, including the given date
    :param end: timestamp (default: tomorrow)
                the reporting end, excluding the given date
    :param status: (default: 'active')
                the status that the tokens have default is 'active' as this is
                relevant for license
    :return: maximum: number of reported tokens with given status in realm
    """
    if status not in STATI:
        raise Exception("unsupported status: %r" % status)

    token_max_count = (
        db.session.query(func.max(Reporting.count))
        .filter(
            and_(
                and_(
                    Reporting.timestamp >= start,
                    Reporting.timestamp < end,
                ),
                Reporting.realm == realm,
                Reporting.parameter == status,
            )
        )
        .scalar()
    )

    if token_max_count is not None:
        return token_max_count

    return -1


def get_last_token_count_before_date(realm, before_date=None, status="active"):
    """Search for latest reporting entry that were set before the given date.

    :param realm: (required)
            the realm in which we are searching
    :param before_date: (required) timestamp
            evaluate all entries before the given date
    :param status: (default: 'active')
            the status that the tokens should have
    :return: counter:
            token count from the reporting event with given status in
            realm or None
    """
    if status not in STATI:
        raise Exception("unsupported status: %r" % status)

    last_token_count_event = (
        db.session.query(Reporting)
        .filter(
            and_(
                Reporting.timestamp < before_date,
                Reporting.realm == realm,
                Reporting.parameter == status,
            )
        )
        .order_by(Reporting.timestamp.desc())
        .first()
    )

    if last_token_count_event:
        return last_token_count_event.count

    return None


def delete(realms, status, date=None):
    """
    delete all rows in reporting database before a given date,
    filtered by realm and status

    :param realms: the ralm to filter
    :param status: the status to filter
    :param date: (optional) day until which all rows will be deleted
    :type date: string in format: 'yyyy-mm-dd'

    :return: number of deleted rows
    """

    if not isinstance(realms, (list, tuple)):
        realms = realms.split(",")

    realm_cond = or_(*(Reporting.realm == realm for realm in realms))
    status_cond = or_(*(Reporting.parameter == stat for stat in status))
    date_cond = Reporting.timestamp < date if date else True

    conds = and_(date_cond, realm_cond, status_cond)

    rows = Reporting.query.filter(conds)
    row_num = rows.count()
    rows.delete()
    return row_num


class ReportingIterator(object):
    """
    support a smooth iterating through lines in reporting table
    """

    def __init__(
        self,
        page=None,
        psize=None,
        sort=None,
        sortdir=None,
        realms=None,
        status=None,
        date=None,
    ):
        """
        constructor of Tokeniterator, which gathers all conditions to build
        a sqalchemy query - iterator

        :param page:     page number
        :type  page:     int
        :param psize:    how many entries per page
        :type  psize:    int
        :param sort:     sort field definition
        :type  sort:     string
        :param sortdir:  sort direction: ascending or descending
        :type  sortdir:  string
        :param realms:   reports from which realms will be shown
        :type realms:    list
        :param status:   filter reports by status like active, unassigned
        :type status:    list
        :param date:     only show entries newer than date
        :type date:      strin gin format 'yyyy-mm-dd'

        :return: - nothing / None
        """
        self.page = 1
        self.pages = 1
        if not isinstance(realms, (list, tuple)):
            realms = realms.split(",")
        if "*" in realms:
            realms = []

        if not isinstance(status, (list, tuple)):
            status = status.split(",")
        if "*" in status:
            status = []

        realm_cond = tuple()
        for realm in realms:
            realm_cond += (or_(func.lower(Reporting.realm) == func.lower(realm)),)

        status_cond = tuple()
        for stat in status:
            status_cond += (or_(Reporting.parameter == stat),)

        date_cond = tuple()
        if date:
            date_cond += (and_(Reporting.timestamp >= date),)

        conds = (
            and_(*date_cond),
            or_(*realm_cond),
            or_(*status_cond),
        )

        if sort is None:
            order = Reporting.timestamp
        elif sort == "event":
            order = Reporting.event
        elif sort == "realm":
            order = Reporting.realm
        elif sort == "parameter":
            order = Reporting.parameter
        elif sort == "value":
            order = Reporting.value
        elif sort == "count":
            order = Reporting.count
        elif sort == "detail":
            order = Reporting.detail
        elif sort == "description":
            order = Reporting.description
        elif sort == "session":
            order = Reporting.session
        else:
            order = Reporting.timestamp

        #  care for the result sort order
        if sortdir is not None and sortdir == "desc":
            order = order.desc()
        else:
            order = order.asc()

        # query database for all reports
        self.reports = Reporting.query.filter(*conds).order_by(order).distinct()
        self.report_num = self.reports.count()
        self.pagesize = self.report_num

        #  care for the result pageing
        if page is not None:
            try:
                if psize is None:
                    pagesize = int(request_context.get("Config").get("pagesize", 50))
                else:
                    pagesize = int(psize)
            except Exception as exce:
                log.debug(
                    "Reporting: Problem with pagesize detected. Exception was: %r",
                    exce,
                )
                pagesize = 20

            try:
                the_page = int(page) - 1
            except Exception as exce:
                log.debug(
                    "Reporting: Problem with page detected. Exception was %r",
                    exce,
                )
                the_page = 0

            if the_page < 0:
                the_page = 0

            start = the_page * pagesize
            stop = (the_page + 1) * pagesize

            self.page = the_page + 1
            fpages = float(self.report_num) / float(pagesize)
            self.pages = int(fpages)
            if fpages - self.pages > 0:
                self.pages += 1
            self.pagesize = pagesize
            self.reports = self.reports.slice(start, stop)

    def getResultSetInfo(self):
        res_set = {
            "pages": self.pages,
            "pagesize": self.pagesize,
            "report_rows": self.report_num,
            "page": self.page,
        }
        return res_set

    def iterate_reports(self):
        try:
            for rep in self.reports:
                desc = json.dumps(rep.get_vars())
                yield desc

        except Exception as exx:
            log.error("Reporting: Problem during iteration.Exception was %r", exx)
