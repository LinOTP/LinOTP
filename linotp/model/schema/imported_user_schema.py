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

from sqlalchemy import schema, types

from linotp.model import db


class ImportedUserSchema(db.Model):

    __tablename__ = "imported_user"
    __table_args__ = {
        "mysql_collate": "utf8_unicode_ci",
        "mysql_charset": "utf8",
    }

    groupid = schema.Column(types.Unicode(100), primary_key=True, index=True)

    userid = schema.Column(types.Unicode(100), primary_key=True, index=True)

    username = schema.Column(types.Unicode(255), default="", index=True)

    phone = schema.Column(types.Unicode(100), default="")

    mobile = schema.Column(types.Unicode(100), default="")

    email = schema.Column(types.Unicode(100), default="")

    surname = schema.Column(types.Unicode(100), default="")

    givenname = schema.Column(types.Unicode(100), default="")

    password = schema.Column(types.Unicode(255), default="", index=True)
