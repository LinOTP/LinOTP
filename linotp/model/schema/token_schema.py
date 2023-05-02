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

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, Sequence, Unicode

from linotp.model import db, implicit_returning
from linotp.model.tokenRealm import TokenRealmSchema


class TokenSchema(db.Model):
    __tablename__ = "Token"
    __table_args__ = {"implicit_returning": implicit_returning}

    LinOtpTokenId = Column(
        "LinOtpTokenId",
        Integer(),
        Sequence("token_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    )

    LinOtpTokenDesc = Column("LinOtpTokenDesc", Unicode(80), default="")
    LinOtpTokenSerialnumber = Column(
        "LinOtpTokenSerialnumber",
        Unicode(40),
        default="",
        unique=True,
        nullable=False,
        index=True,
    )

    LinOtpTokenType = Column(
        "LinOtpTokenType", Unicode(30), default="HMAC", index=True
    )
    LinOtpTokenInfo = Column("LinOtpTokenInfo", Unicode(2000), default="")
    # # encrypt
    LinOtpTokenPinUser = Column("LinOtpTokenPinUser", Unicode(512), default="")
    # # encrypt
    LinOtpTokenPinUserIV = Column(
        "LinOtpTokenPinUserIV", Unicode(32), default=""
    )
    # # encrypt
    LinOtpTokenPinSO = Column("LinOtpTokenPinSO", Unicode(512), default="")
    # # encrypt
    LinOtpTokenPinSOIV = Column("LinOtpTokenPinSOIV", Unicode(32), default="")
    LinOtpIdResolver = Column(
        "LinOtpIdResolver", Unicode(120), default="", index=True
    )
    LinOtpIdResClass = Column("LinOtpIdResClass", Unicode(120), default="")
    LinOtpUserid = Column("LinOtpUserid", Unicode(320), default="", index=True)
    LinOtpSeed = Column("LinOtpSeed", Unicode(32), default="")
    LinOtpOtpLen = Column("LinOtpOtpLen", Integer(), default=6)
    # # hashed
    LinOtpPinHash = Column("LinOtpPinHash", Unicode(512), default="")
    # # encrypt
    LinOtpKeyEnc = Column("LinOtpKeyEnc", Unicode(1024), default="")
    LinOtpKeyIV = Column("LinOtpKeyIV", Unicode(32), default="")
    LinOtpMaxFail = Column("LinOtpMaxFail", Integer(), default=10)
    LinOtpIsactive = Column("LinOtpIsactive", Boolean(), default=True)
    LinOtpFailCount = Column("LinOtpFailCount", Integer(), default=0)
    LinOtpCount = Column("LinOtpCount", Integer(), default=0)
    LinOtpCountWindow = Column("LinOtpCountWindow", Integer(), default=10)
    LinOtpSyncWindow = Column("LinOtpSyncWindow", Integer(), default=1000)
    LinOtpCreationDate = Column(
        "LinOtpCreationDate",
        DateTime,
        index=True,
        default=datetime.now().replace(microsecond=0),
    )

    LinOtpLastAuthSuccess = Column(
        "LinOtpLastAuthSuccess",
        DateTime,
        index=True,
        default=None,
    )

    LinOtpLastAuthMatch = Column(
        "LinOtpLastAuthMatch", DateTime, index=True, default=None
    )

    realms = db.relationship(
        "Realm",
        secondary=TokenRealmSchema.__table__,
        lazy="subquery",
        backref=db.backref("tokens", lazy=True),
    )
