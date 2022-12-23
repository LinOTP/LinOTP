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

"""linotp admin command.

linotp admin  fix-db-encoding

"""
import sys

from flask import current_app
from flask.cli import AppGroup, with_appcontext

from linotp.model import fix_db_encoding, setup_db

admin_cmds = AppGroup(
    "admin",
    help="Administrative commands to manage the linotp application server.",
)

# ------------------------------------------------------------------------- --
# Command `linotp admin fix-db-encoding`
# ------------------------------------------------------------------------- --


@admin_cmds.command(
    "fix-db-encoding",
    help=(
        """Fix encoding of database entries of python2+mysql database
by converting data from iso latin encoding to utf8 encoding.
Affected data might be Config values (Config.Value) and description
(Config.Description), Token info (Token.LinOtpTokenInfo) and description
(Token.LinOtpTokenDesc) entries as well as User data (imported_user.username),
(imported_user.surname), (imported_user.givenname), and (imported_user.email) entries.
"""
    ),
)
@with_appcontext
def fix_db_encoding_command():
    """Fix the python2+mysql iso8859 encoding by conversion to utf-8."""

    try:
        # Even though we skip initialising the database when doing
        # `linotp init …`, at this point we do need a database engine
        # after all.
        setup_db(current_app)
        result, response = fix_db_encoding(current_app)

    except Exception as exx:
        current_app.echo(f"Conversion could not be completed: {exx}")
        sys.exit(1)

    if not result:
        current_app.echo(f"Conversion failed: {response}")
        sys.exit(1)

    current_app.echo(f"Conversion response: {response}")
    sys.exit(0)
