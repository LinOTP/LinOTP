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

import pytest

from linotp.lib.crypto import utils
from linotp.lib.tools.set_password import DataBaseContext, SetPasswordHandler


@pytest.fixture
def db_context(app):
    return DataBaseContext("")  # no URI needed


def check_for_exception(
    pw_handler, username, old_password, new_password, exception, message
):
    """
    check that an exception with the message will be raised
    """
    with pytest.raises(exception) as exx:
        pw_handler.set_password(username, old_password, new_password)

    assert message in str(exx.value)


def test_set_password(app, db_context):
    # first create the user table
    SetPasswordHandler.create_table(db_context)

    admin_user = "admin"

    admin_pw = utils.crypt_password("admin_password")
    # setup the inital user and it's password

    SetPasswordHandler.create_admin_user(
        db_context, username=admin_user, crypted_password=admin_pw
    )

    # run a valid change of the admin password

    pw_handler = SetPasswordHandler(db_context)
    pw_handler.set_password(admin_user, "admin_password", "new_password")


@pytest.mark.parametrize(
    "user,oldpw,newpw,exception,message",
    [
        (
            "username",
            "old_password",
            "new_password",
            Exception,
            "no user 'username' found!",
        ),
        (
            "admin",
            "foobar",
            "new_password",
            Exception,
            "old password missmatch!",
        ),
        (
            "admin",
            "old_password",
            None,
            Exception,
            "must be unicode or bytes, not None",
        ),
        (
            "admin",
            "old_password",
            123456,
            Exception,
            "must be unicode or bytes, not int",
        ),
        (
            "admin",
            "old_password",
            1234.56,
            Exception,
            "must be unicode or bytes, not float",
        ),
        (
            "admin",
            "old_password",
            db_context,
            Exception,
            "must be unicode or bytes, not _pytest.fixtures.FixtureFunctionDefinition",
        ),
    ],
)
def test_set_password_various(app, db_context, user, oldpw, newpw, exception, message):
    SetPasswordHandler.create_table(db_context)
    pw_handler = SetPasswordHandler(db_context)
    admin_user = "admin"
    admin_pw = utils.crypt_password("old_password")
    SetPasswordHandler.create_admin_user(
        db_context, username=admin_user, crypted_password=admin_pw
    )

    check_for_exception(pw_handler, user, oldpw, newpw, exception, message)

    # make sure that the password did not change in between and the
    # password could be set correctly

    pw_handler.set_password("admin", "old_password", "admin_password")


def test_set_password_with_no_table(app, db_context):
    """
    try to set password though no table exists
    """

    pw_handler = SetPasswordHandler(db_context)
    SetPasswordHandler.AdminUser.__table__.drop(db_context.get_engine())

    msg = "no such table: admin_users"
    check_for_exception(
        pw_handler,
        "admin",
        "admin_password",
        "new_password",
        Exception,
        message=msg,
    )


def test_set_inital_admin_twice(app, db_context):
    # first create the user table
    SetPasswordHandler.create_table(db_context)

    admin_user = "admin"
    admin_pw = utils.crypt_password("admin_password")

    # setup the inital user and it's password

    SetPasswordHandler.create_admin_user(
        db_context, username=admin_user, crypted_password=admin_pw
    )

    admin_user = "admin"
    admin_pw = utils.crypt_password("password_of_admin")

    # setup the inital user and try to set it's password a second time
    # - this will fail as the user could only be set once

    SetPasswordHandler.create_admin_user(
        db_context, username=admin_user, crypted_password=admin_pw
    )

    pw_handler = SetPasswordHandler(db_context)

    msg = "old password missmatch!"
    check_for_exception(
        pw_handler,
        "admin",
        "password_of_admin",
        "new_password",
        Exception,
        message=msg,
    )

    pw_handler.set_password("admin", "admin_password", "new_password")


# eof #
