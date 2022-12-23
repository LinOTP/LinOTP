#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP userid resolvers.
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

import tempfile

import pytest

from linotp.useridresolver.PasswdIdResolver import IdResolver as PasswdResolver
from linotp.useridresolver.UserIdResolver import ResolverLoadConfigError


@pytest.fixture
def passwd_resolver():
    content = """user1:0DM4AJtW/rTYY:10:10:User Eins:Irgendwas:Nochmal
user2:.4UO1mxvTmdM6:11:11:User Zwei:Irgendwas:Nochmal"""

    with tempfile.NamedTemporaryFile(mode="w+") as f:
        f.write(content)
        f.flush()

        pw_file = f.name

        pw_config = {"linotp.passwdresolver.fileName.my": pw_file}
        y = PasswdResolver()
        y.loadConfig(pw_config, "my")

        yield y


def test_getUserId(passwd_resolver):
    """test the existance of the user1 and user2"""
    y = passwd_resolver

    res = y.getUserId("user1")
    assert res == "10"

    assert y.getUserInfo(res).get("surname") == "Eins"

    res = y.getUserId("user2")
    assert res == "11"

    assert y.getUserInfo(res).get("surname") == "Zwei"


def test_resolver_fail():
    """
    Test to use a file, that does not exist
    """
    pw_config = {
        "linotp.passwdresolver.fileName.my": "/dev/shm/this_file_does_not_exist"
    }

    msg = (
        "File '/dev/shm/this_file_does_not_exist' does not "
        "exist or is not accesible"
    )

    with pytest.raises(ResolverLoadConfigError, match=msg):

        y = PasswdResolver()
        y.loadConfig(pw_config, "my")


def test_checkpass(passwd_resolver):
    """
    Check the password of user1 and user 2
    """
    y = passwd_resolver
    assert y.checkPass(y.getUserId("user1"), "pwU1")
    assert y.checkPass(y.getUserId("user2"), "pwU2")


def test_getUserList(passwd_resolver):
    """
    testing the userlist
    """
    # all users are two users
    y = passwd_resolver
    user_list = y.getUserList({})
    assert len(user_list) == 2

    # there is only one user that ends with '1'
    user_list = y.getUserList({"username": "*1"})
    assert len(user_list) == 1


def test_getUsername(passwd_resolver):
    """
    testing getting the username
    """
    y = passwd_resolver
    assert y.getUsername("10")
    assert y.getUsername("11")
    assert not y.getUsername("9")


# eof #
