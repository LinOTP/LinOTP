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

    subq = Session.query(
        func.max(Reporting.count))\
        .filter(and_(Reporting.parameter == status, Reporting.realm == realm))

    max = Session.query(Reporting.count)\
        .filter(and_(
        Reporting.parameter == status,
        Reporting.realm == realm,
        Reporting.count == subq))

    result = max.first()[0]

    return result


def delete_reporting():
    """
    delete all rows in reporting database

    :return: number of deleted rows
    """
    rows = Session.query(Reporting)
    row_num = rows.count()
    for row in rows.all():
        Session.delete(row)
    return row_num


def delete_before(date):
    """
    delete all rows in reporting database before a given date

    :param date: day until which all rows will be deleted
    :type date: string in format: 'yyyy-mm-dd'

    :return: number of deleted rows
    """
    rows = Session.query(Reporting).filter(Reporting.timestamp < date)
    row_num = rows.count()

    for row in rows:
        Session.delete(row)
    return row_num




