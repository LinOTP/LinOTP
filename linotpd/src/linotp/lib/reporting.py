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
import logging

from linotp.model import Reporting
from linotp.model.meta import Session

from linotp.lib.monitoring import MonitorHandler
from linotp.lib.policy import check_token_reporting

from sqlalchemy import (and_, or_, not_)
from sqlalchemy import func

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
        realms = ['/:no realm:/']
    elif not isinstance(tokenrealms, (list, tuple)):
        realms = [tokenrealms]

    for realm in realms:
        action = check_token_reporting(realm)
        mh = MonitorHandler()
        counters = mh.token_count(realm, action[:])
        for key, val in counters.items():
            report = Reporting(
                event=event, realm=realm, parameter=key, count=val)
            try:
                Session.add(report)
            except Exception as exce:
                log.exception('[save]Error during saving Report: %r' % exce)


def get_max(realm, status='active'):
    """
    get the maximum number of tokens (with given status) in a realm in the whole
     reporting database;
     if no status is given, 'active' is default

    :param realm: (required) the realm in which we are searching
    :param status: (default: 'active') the status that the tokens have
            defaukt is active as this is relevant for license
    :return: maximum number of reported tokens with given status in realm
    """

    max = Session.query(
        func.max(Reporting.count))\
        .filter(and_(Reporting.parameter == status, Reporting.realm == realm))

    result = max.first()[0]

    return result


def delete(realms, status, date=None):
    """
    delete all rows in reporting database before a given date

    :param date: (optional)day until which all rows will be deleted
    :type date: string in format: 'yyyy-mm-dd'

    :return: number of deleted rows
    """

    if not isinstance(realms, (list, tuple)):
        realms = realms.split(',')

    realm_cond = tuple()
    for realm in realms:
       realm_cond += (or_(Reporting.realm == realm),)

    status_cond = tuple()
    for stat in status:
        status_cond += (or_(Reporting.parameter == stat),)

    date_cond = tuple()
    if date:
        date_cond += (and_(Reporting.timestamp < date),)

    conds = (and_(*date_cond), or_(*realm_cond), or_(*status_cond),)

    rows = Session.query(Reporting).filter(*conds)
    row_num = rows.count()

    for row in rows:
        Session.delete(row)
    return row_num


class ReportingIterator(object):
    """
    support a smooth iterating through lines in reporting table
    """

    def __init__(self, page=None, psize=None, sort=None, sortdir=None,
                 realms=None, status=None, date=None):
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
            realms = realms.split(',')
        if not isinstance(status, (list, tuple)):
            status = status.split(',')

        realm_cond = tuple()
        for realm in realms:
            realm_cond += (or_(Reporting.realm == realm),)

        status_cond = tuple()
        for stat in status:
            status_cond += (or_(Reporting.parameter == stat),)

        date_cond = tuple()
        if date:
            date_cond += (and_(Reporting.timestamp >= date),)

        conds = (and_(*date_cond), or_(*realm_cond), or_(*status_cond),)

        if sort is None:
            order = Reporting.timestamp
        elif sort == 'event':
            order = Reporting.event
        elif sort == 'realm':
            order = Reporting.realm
        elif sort == 'parameter':
            order = Reporting.parameter
        elif sort == 'value':
            order = Reporting.value
        elif sort == 'count':
            order = Reporting.count
        elif sort == 'detail':
            order = Reporting.detail
        elif sort == 'description':
            order = Reporting.description
        elif sort == 'session':
            order = Reporting.session
        else:
            order = Reporting.timestamp

        #  care for the result sort order
        if sortdir is not None and sortdir == "desc":
            order = order.desc()
        else:
            order = order.asc()

        #  care for the result pageing
        if page is None:
            self.reports = Session.query(Reporting).filter(*conds).\
                order_by(order).distinct()
            self.report_num = self.reports.count()

            log.debug("[ReportingIterator] DB-Query returned # of objects:"
                      " %i" % self.report_num)
            self.pagesize = self.report_num
            self.it = iter(self.reports)
            return

    def getResultSetInfo(self):
        resSet = {"pages": self.pages,
                  "pagesize": self.pagesize,
                  "report_rows": self.report_num,
                  "page": self.page
                  }
        return resSet

    def next(self):
        log.debug("[next] ReportingIterator finds next report")

        rep = self.it.next()
        desc = rep.get_vars()
        return desc

    def __iter__(self):
        log.debug("[__iter__] ReportingIterator")
        return self

