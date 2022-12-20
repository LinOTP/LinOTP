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

""" linotp local-admins commands.

linotp local-admins list
linotp local-admins add
linotp local-admins modify
linotp local-admins password
linotp local-admins remove
linotp local-admins enable

"""

import click

from flask import current_app
from flask.cli import AppGroup

from linotp.model.local_admin_user import (
    DuplicateUserError,
    LocalAdminResolver,
    NoSuchUserError,
)

local_admins_cmds = AppGroup(
    "local-admins", help="Manage local administrator accounts"
)


# ----------------------------------------------------------------------
# Command `linotp local-admins list`
# ----------------------------------------------------------------------


@local_admins_cmds.command("list", help="List local administrator accounts")
@click.option("--format", "-f", help="Output format template")
@click.option("--long", "-l", is_flag=True, help="Detailed output")
def list_cmd(format, long):
    """Lists local administrator accounts."""
    format = format or (
        "{username}:{name}:{email}:{phone}:{mobile}" if long else "{username}"
    )

    res = LocalAdminResolver(current_app)
    for user_info in res.list_users():
        user_info[
            "name"
        ] = f"{user_info['givenname']} {user_info['surname']}".strip()
        try:
            print(format.format_map(user_info))
        except KeyError as ex:
            raise click.ClickException(f"invalid key {ex!s} in template")


# ----------------------------------------------------------------------
# Command `linotp local-admins add ACCOUNT-NAME`
# ----------------------------------------------------------------------


@local_admins_cmds.command("add", help="Add a local administrator account")
@click.option(
    "--phone", default="", help="Phone number associated with the account"
)
@click.option(
    "--mobile", default="", help="Mobile number associated with the account"
)
@click.option(
    "--email", default="", help="Email address associated with the account"
)
@click.option("--surname", default="", help="Surname of the account owner")
@click.option(
    "--givenname", default="", help="Given name of the account owner"
)
@click.argument("account_name")
def add_cmd(phone, mobile, email, surname, givenname, account_name):
    """Adds a new local administrator account.

    If the account name already exists as a local administrator, the command
    fails.
    """

    res = LocalAdminResolver(current_app)
    try:
        res.add_user(
            account_name,
            password="",
            surname=surname,
            givenname=givenname,
            phone=phone,
            mobile=mobile,
            email=email,
        )
    except DuplicateUserError as ex:
        raise click.ClickException(ex)


# ----------------------------------------------------------------------
# Command `linotp local-admins modify ACCOUNT-NAME`
# ----------------------------------------------------------------------
# This wasn't in the original spec but we need it.
# ----------------------------------------------------------------------


@local_admins_cmds.command(
    "modify", help="Modify a local administrator account"
)
@click.option(
    "--phone", default=None, help="Phone number associated with the account"
)
@click.option(
    "--mobile", default=None, help="Mobile number associated with the account"
)
@click.option(
    "--email", default=None, help="Email address associated with the account"
)
@click.option("--surname", default=None, help="Surname of the account owner")
@click.option(
    "--givenname", default=None, help="Given name of the account owner"
)
@click.argument("account_name")
def modify_cmd(phone, mobile, email, surname, givenname, account_name):

    res = LocalAdminResolver(current_app)
    try:
        user_info = res.get_user_info(account_name)
    except NoSuchUserError as ex:
        raise click.ClickException(ex)

    for k, v in zip(
        ("surname", "givenname", "phone", "mobile", "email"),
        (surname, givenname, phone, mobile, email),
    ):
        if v is not None:
            user_info[k] = v

    try:
        res.update_user(account_name, **user_info)
    except NoSuchUserError as ex:  # possible race condition
        raise click.ClickException(ex)


# ----------------------------------------------------------------------
# Command `linotp local-admins password ACCOUNT-NAME`
# ----------------------------------------------------------------------


@local_admins_cmds.command(
    "password", help="Change password for a local administrator account"
)
@click.password_option()
@click.argument("account_name")
def password_cmd(password, account_name):

    if password == "-":  # read password from stdin, for scripts
        password = input()

    # Insert password policy checks here.

    res = LocalAdminResolver(current_app)
    try:
        res.set_user_password(account_name, password)
    except NoSuchUserError as ex:
        raise click.ClickException(ex)


# ----------------------------------------------------------------------
# Command `linotp local-admins remove ACCOUNT-NAME`
# ----------------------------------------------------------------------


@local_admins_cmds.command(
    "remove", help="Remove a local administrator account"
)
@click.confirmation_option(
    prompt="Are you sure you want to remove the account?"
)
@click.argument("account_name")
def remove_cmd(account_name):

    res = LocalAdminResolver(current_app)
    try:
        res.remove_user(account_name)
    except NoSuchUserError as ex:
        raise click.ClickException(ex)


# ----------------------------------------------------------------------
# Command `linotp local-admins enable`
# ----------------------------------------------------------------------


@local_admins_cmds.command(
    "enable", help="(Re-)Add local admin resolver to admin realm"
)
def enable_cmd():

    res = LocalAdminResolver(current_app)
    current_app.echo("Adding local admin resolver to admin realm", v=1)
    res.add_to_admin_realm()
    current_app.echo("Done", v=1)
