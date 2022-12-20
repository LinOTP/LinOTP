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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, Sequence, String

from linotp.model import db, implicit_returning


class ReportingSchema(db.Model):

    __tablename__ = "REPORTING"
    __table_args__ = {"implicit_returning": implicit_returning}

    id = Column(
        "R_ID",
        Integer,
        Sequence("reporting_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    )
    timestamp = Column("R_TIMESTAMP", DateTime, default=datetime.now())
    event = Column("R_EVENT", String(250), default="")
    realm = Column("R_REALM", String(250), default="")
    parameter = Column("R_PARAMETER", String(250), default="")
    value = Column("R_VALUE", String(250), default="")
    count = Column("R_COUNT", Integer(), default=0)
    detail = Column("R_DETAIL", String(2000), default="")
    session = Column("R_SESSION", String(250), default="")
    description = Column("R_DESCRIPTION", String(2000), default="")
