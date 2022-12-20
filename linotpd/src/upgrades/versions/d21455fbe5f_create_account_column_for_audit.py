# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
"""extend Config Value column

Revision ID: d21455fbe5f
Revises: e834dd143cf
Create Date: 2014-10-02 18:04:44.493146

"""

# revision identifiers, used by Alembic.
revision = 'd21455fbe5f'
down_revision = 'e834dd143cf'

from alembic import op
import sqlalchemy as sa
from sqlalchemy import MetaData


def upgrade(engine_name):
    globals()["upgrade_%s" % engine_name]()


def downgrade(engine_name):
    globals()["downgrade_%s" % engine_name]()

def upgrade_linotp():
    op.alter_column(
        table_name='Config',
        column_name='Value',
        nullable=True,
        type_=sa.types.Unicode(length=3000),
    )

def downgrade_linotp():
    op.alter_column(
        table_name='Config',
        column_name='Value',
        nullable=True,
        type_=sa.types.Unicode(length=2000),
    )


def upgrade_audit():
    pass

def downgrade_audit():
    pass

def upgrade_openid():
    pass

def downgrade_openid():
    pass

