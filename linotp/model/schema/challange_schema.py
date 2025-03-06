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


from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    LargeBinary,
    Sequence,
    String,
)

from linotp.model import COL_PREFIX, db

session_column = "%ssession" % COL_PREFIX
timestamp_column = "%stimestamp" % COL_PREFIX


class ChallengeSchema(db.Model):
    """
    the generic challange handling
    """

    __tablename__ = "challenges"

    id = Column(
        "id",
        Integer(),
        Sequence("token_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    )
    transid = Column(
        "transid", String(64), unique=True, nullable=False, index=True
    )
    ptransid = Column("ptransid", String(64), index=True)
    odata = Column("data", String(512), default="")
    data = Column("bdata", LargeBinary, default=None)
    oochallenge = Column("challenge", String(512), default="")
    ochallenge = Column("lchallenge", String(2000), default="")
    challenge = Column("bchallenge", LargeBinary, default=None)
    session = Column(session_column, String(512), default="")
    tokenserial = Column("tokenserial", String(64), default="", index=True)
    timestamp = Column(timestamp_column, DateTime)
    received_count = Column("received_count", Integer, default=False)
    received_tan = Column("received_tan", Boolean, default=False)
    valid_tan = Column("valid_tan", Boolean, default=False)
