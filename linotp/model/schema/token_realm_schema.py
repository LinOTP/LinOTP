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

from sqlalchemy import Column, ForeignKey, Integer, Sequence

from linotp.model import db, implicit_returning


class TokenRealmSchema(db.Model):
    __tablename__ = "TokenRealm"
    __table_args__ = {"implicit_returning": implicit_returning}

    id = Column(
        "id",
        Integer(),
        Sequence("tokenrealm_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    )
    token_id = Column("token_id", Integer(), ForeignKey("Token.LinOtpTokenId"))
    realm_id = Column("realm_id", Integer(), ForeignKey("Realm.id"))
