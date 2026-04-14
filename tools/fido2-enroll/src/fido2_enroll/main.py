#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is an unsupported contribution to the LinOTP server.
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

"""
FIDO2/WebAuthn token bulk rollout

Use this script for inspiration if you need to mass-rollout FIDO2 tokens
(possibly with associated FIDO2 authenticators) and don't want to enter
them one by one in the LinOTP admin UI.
"""

import pathlib
import sys

import click

from .enroll import enroll_token


@click.command(
    epilog="""For users given as USERNAME without a REALM, the REALM
    defaults initially to the value of the `--realm` option. If no
    `--realm` option is given, REALM will be prompted for
    interactively. For subsequent USERNAMEs without a REALM, the REALM
    is the most recent value that was previously determined. IOW,
    specifying `foo@bar baz` will consider user `baz` to be in the
    `bar` realm, too.

    `fido2-enroll foo@bar` creates a token for user `foo` in realm `bar`.
    `fido2-enroll foo@bar baz` uses realm `bar` for both `foo` and `baz`,
    as does `fido2-enroll --realm bar foo baz`.
    `fido2-enroll --realm bar foo baz@quux bla` uses realm `bar` for
    user `foo` and realm `quux` for users `baz` and `bla`.
    """
)
@click.option(
    "--admin-user",
    "-U",
    envvar="FIDO2_ENROLL_ADMIN_USER",
    default="admin",
    show_default=True,
    help="Admin user name for LinOTP access.",
)
@click.option(
    "--admin-password",
    "-P",
    default="",
    help="Admin password for LinOTP access.",
)
@click.option(
    "--admin-credentials",
    "-C",
    type=click.Path(path_type=pathlib.Path),
    envvar="FIDO2_ENROLL_ADMIN_CREDENTIALS",
    default="~/.config/fido2-enroll/admin-credentials",
    help="File containing `admin-user:admin-password` for LinOTP access.",
)
@click.option(
    "--base-url",
    "-B",
    envvar="FIDO2_ENROLL_BASE_URL",
    default="https://linotp.example.com",
    help="Base URL for LinOTP server",
)
@click.option(
    "--ca-file",
    envvar="FIDO2_ENROLL_CA_FILE",
    default="/etc/ssl/certs/ca-certificates.crt",
    show_default=True,
    help="Root CA certificate file for LinOTP server.",
)
@click.option(
    "--pair/--no-pair",
    envvar="FIDO2_ENROLL_PAIR",
    default=True,
    show_default=True,
    help="Whether to associate the token(s) with a FIDO2 authenticator.",
)
@click.option(
    "--pause/--no-pause",
    envvar="FIDO2_ENROLL_PAUSE",
    default=True,
    show_default=True,
    help="Whether to pause after each token when enrolling multiple tokens at the same time (e.g., to change FIDO2 authenticators).",
)
@click.option(
    "--dry-run/--no-dry-run",
    envvar="FIDO2_ENROLL_DRY_RUN",
    default=False,
    show_default=True,
    help="Whether to actually try to enroll tokens in LinOTP, or just go through the motions without calling LinOTP.",
)
@click.option(
    "--realm", "-r", envvar="FIDO2_ENROLL_REALM", default="", help="Realm for token(s)"
)
@click.option(
    "--verbose/--no-verbose",
    envvar="FIDO2_ENROLL_VERBOSE",
    default=True,
    show_default=True,
    help="Whether to display a running commentary.",
)
@click.argument("users", nargs=-1)
def enroll(
    admin_user,
    admin_password,
    admin_credentials,
    base_url,
    ca_file,
    pair,
    pause,
    dry_run,
    realm,
    verbose,
    users,
):
    """Roll out FIDO2 tokens for users. Each user can be given as
    USERNAME or USERNAME@REALM."""

    admin_credentials = admin_credentials.expanduser()
    if admin_credentials.exists():
        credentials = admin_credentials.read_text()
        admin_user, admin_password = credentials.strip().split(":", 1)
    if not admin_user:
        admin_user = click.prompt("LinOTP admin user")
    if not admin_password:
        admin_password = click.prompt("LinOTP admin password", hide_input=True)

    if not users:
        users = click.prompt("User (use space to separate multiple users)").split()

    for k, user in enumerate(users):
        user, sep, user_realm = user.partition("@")
        if user_realm:
            realm = user_realm
        elif not realm:
            realm = click.prompt("Realm")

        try:
            if dry_run:
                click.echo(f"Enrolling token for {user}@{realm}")
            else:
                enroll_token(
                    user,
                    realm=realm,
                    base_url=base_url,
                    ca_file=ca_file,
                    admin_user=admin_user,
                    admin_password=admin_password,
                    pair=pair,
                    verbose=verbose,
                )
        except Exception as ex:
            click.echo(f"Error: {ex!s}", err=True)
            sys.exit(1)

        if pause and k < len(users) - 1:
            click.prompt("Press RETURN to continue", default="", show_default=False)

    if verbose and len(users) > 1:
        click.echo("All done!")


def main() -> None:
    enroll()
