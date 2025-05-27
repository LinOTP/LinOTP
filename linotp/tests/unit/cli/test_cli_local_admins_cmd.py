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
#
"""LinOTP test for `linotp local-admins` command group."""

from dataclasses import dataclass

import passlib
import pytest

from linotp.cli import main as cli_main
from linotp.lib.config import getFromConfig
from linotp.model.config import set_config
from linotp.model.local_admin_user import (
    DuplicateUserError,
    LocalAdminResolver,
    NoSuchUserError,
)


@dataclass
class LAUser:
    username: str
    givenname: str = ""
    surname: str = ""
    phone: str = ""
    mobile: str = ""
    email: str = ""


LOCAL_ADMIN_PASSWORD = "secret123"
LOCAL_ADMINS = [
    LAUser("hugo", "Hugo", email="hugo@example.com"),
    LAUser("susi", "Susi", "Sorglos", phone="+491234567890"),
    LAUser("x123", surname="X", mobile="+491609876543"),
]


@pytest.fixture
def runner(app):
    return app.test_cli_runner(mix_stderr=False)


@pytest.fixture
def resolver(app):
    res = LocalAdminResolver(app)
    res._remove_all_users()
    for a in LOCAL_ADMINS:
        obj = res.user_class(
            userid=a.username,
            groupid=res.admin_resolver_name,
            username=a.username,
            password=res._encrypt_password(LOCAL_ADMIN_PASSWORD),
            surname=a.surname,
            givenname=a.givenname,
            phone=a.phone,
            mobile=a.mobile,
            email=a.email,
        )
        res.session.add(obj)
    res.session.commit()
    return res


@pytest.mark.parametrize(
    "options,expected",
    [
        ([], "hugo\nsusi\nx123\n"),
        (
            ["--long"],
            "hugo:Hugo:hugo@example.com::\n"
            "susi:Susi Sorglos::+491234567890:\n"
            "x123:X:::+491609876543\n",
        ),
        (
            ["--format=name={username}/mail={email}"],
            "name=hugo/mail=hugo@example.com\nname=susi/mail=\nname=x123/mail=\n",
        ),
        (["--format={username}", "--long"], "hugo\nsusi\nx123\n"),
    ],
)
def test_local_admins_list(app, runner, resolver, options, expected):
    result = runner.invoke(cli_main, ["local-admins", "list"] + options)
    assert result.exit_code == 0
    assert result.output == expected


def test_local_admins_list_invalid_key(app, runner, resolver):
    # We need the `resolver` fixture in order to have some users in the
    # table. Otherwise the template will never be used and the invalid
    # key will never be detected.

    result = runner.invoke(cli_main, ["local-admins", "list", "--format", "{foo}"])
    print(result)
    assert result.exit_code == 1
    assert "Error: invalid key 'foo' in template" in result.stderr


@pytest.mark.parametrize(
    "username,args",
    [
        ("user1", {"givenname": "Monika", "surname": "Mustermann"}),
        ("user2", {"email": "fritz@example.com"}),
        ("user3", {"phone": "+491111111111", "mobile": "+49222222222"}),
        ("user4", {}),
        (
            "user5",
            {
                "givenname": "Никола́й Андре́евич",
                "surname": "Ри́мский-Ко́рсаков",
                "email": "bumblebee@example.com",
                "phone": "+7812456789",
                "mobile": "+7111111111",
            },
        ),
    ],
)
def test_local_admins_add(app, runner, resolver, username, args):
    result = runner.invoke(
        cli_main,
        ["local-admins", "add"] + [f"--{k}={v}" for k, v in args.items()] + [username],
    )
    assert result.exit_code == 0
    u = resolver.session.query(resolver.user_class).get(
        (resolver.admin_resolver_name, username)
    )
    assert u.groupid == resolver.admin_resolver_name
    assert u.username == username
    assert u.password == "*"
    all_keys = {"givenname", "surname", "email", "phone", "mobile"}
    for k in args:  # check attributes in the call
        assert getattr(u, k) == args[k]
        all_keys.discard(k)
    for k in all_keys:  # check attributes not in the call
        assert getattr(u, k) == ""


def test_local_admins_add_duplicate_user(app, runner, resolver):
    result = runner.invoke(cli_main, ["local-admins", "add", "hugo"])
    assert result.exit_code == 1
    assert "Error: User hugo already exists" in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        {"givenname": "Foo"},
        {"surname": "Foo"},
        {"email": "foo@example.com"},
        {"phone": "+49999999999"},
        {"mobile": "+49999999999"},
        {"givenname": "Foo", "surname": "Foo"},
        {
            "givenname": "Foo",
            "surname": "Foo",
            "email": "foo@example.com",
            "phone": "+49999999999",
            "mobile": "+49999999999",
        },
        {},
    ],
)
def test_local_admins_modify(app, runner, resolver, args):
    username = "hugo"
    all_keys = {"givenname", "surname", "email", "phone", "mobile"}
    orig_u = resolver.session.query(resolver.user_class).get(
        (resolver.admin_resolver_name, username)
    )
    result = runner.invoke(
        cli_main,
        ["local-admins", "modify"]
        + [f"--{k}={v}" for k, v in args.items()]
        + [username],
    )
    assert result.exit_code == 0
    u = resolver.session.query(resolver.user_class).get(
        (resolver.admin_resolver_name, username)
    )
    for k in all_keys:
        v = args[k] if k in args else getattr(orig_u, k)
        assert getattr(u, k) == v


def test_local_admins_modify_missing_user(app, runner, resolver):
    result = runner.invoke(cli_main, ["local-admins", "modify", "xyzzy"])
    assert result.exit_code == 1
    assert "Error: User xyzzy does not exist" in result.stderr


@pytest.mark.parametrize(
    "pwd,args,stdin_data",
    [
        ("foo", [], "{PWD}\n{PWD}\n"),
        ("bar", ["--password={PWD}"], ""),
        ("baz", [f"--password=-"], "{PWD}\n"),
    ],
)
def test_local_admins_password(app, runner, resolver, pwd, args, stdin_data):
    username = "hugo"
    args = [arg.replace("{PWD}", pwd) for arg in args]
    stdin_data = stdin_data.replace("{PWD}", pwd)

    result = runner.invoke(
        cli_main,
        ["local-admins", "password"] + args + [username],
        input=stdin_data,
    )

    assert result.exit_code == 0
    u = resolver.session.query(resolver.user_class).get(
        (resolver.admin_resolver_name, username)
    )

    # This must match whatever the LinOTP code uses.
    assert passlib.hash.sha512_crypt.verify(pwd, u.password)


def test_local_admins_password_missing_user(app, runner, resolver):
    # We need to specify a password here, or else the test will hang
    # waiting for one.
    result = runner.invoke(
        cli_main, ["local-admins", "password", "--password=foo", "xyzzy"]
    )
    assert result.exit_code == 1
    assert "Error: User xyzzy does not exist" in result.stderr


@pytest.mark.parametrize(
    "args,stdin_data,gone",
    [
        ([], "y\n", True),
        ([], "n\n", False),
        (["--yes"], "", True),
    ],
)
def test_local_admins_remove(app, runner, resolver, args, stdin_data, gone):
    username = "hugo"
    result = runner.invoke(
        cli_main,
        ["local-admins", "remove"] + args + [username],
        input=stdin_data,
    )
    assert result.exit_code == (0 if gone else 1)
    if not args:
        assert "Are you sure you want to remove the account?" in result.output
    u = resolver.session.query(resolver.user_class).get(
        (resolver.admin_resolver_name, username)
    )
    if gone:
        assert not u
    else:
        assert u.username == username


def test_local_admins_remove_missing_user(app, runner, resolver):
    result = runner.invoke(cli_main, ["local-admins", "remove", "--yes", "xyzzy"])
    assert result.exit_code == 1
    assert "Error: User xyzzy does not exist" in result.stderr


@pytest.mark.parametrize("res_list", ["", "foo,bar,baz"])
def test_local_admins_enable_command(app, runner, resolver, res_list):
    # Forcibly remove the resolver from the admin realm.
    admin_realm_name = app.config["ADMIN_REALM_NAME"].lower()
    admin_resolvers_key = f"useridresolver.group.{admin_realm_name}"

    set_config(
        key=admin_resolvers_key,
        value=res_list,
        typ="text",
        description="None",
    )
    resolver.session.commit()

    # Try to re-add it using the enable command.
    result = runner.invoke(cli_main, ["local-admins", "enable"])

    assert result.exit_code == 0

    # See whether it is there now.
    admin_resolvers = getFromConfig(admin_resolvers_key, "")
    if admin_resolvers:
        first_resolver = admin_resolvers.split(",")[0].strip()
        assert (
            first_resolver
            == "useridresolver.SQLIdResolver.IdResolver." + resolver.admin_resolver_name
        )
    else:
        assert False, "still no resolvers in admin realm"
