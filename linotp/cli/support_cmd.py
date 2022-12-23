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

linotp support set license_file
linotp support get
linotp support verify [-f license_file]

"""
import json
import sys

import click

from flask import current_app
from flask.cli import AppGroup, with_appcontext

from linotp.app import allocate_security_module, set_config
from linotp.lib.support import (
    InvalidLicenseException,
    getSupportLicenseInfo,
    isSupportLicenseValid,
    parseSupportLicense,
    setSupportLicense,
)
from linotp.model import db

support_cmds = AppGroup(
    "support",
    help="Administrative commands to set and query the linotp support.",
)


def _setup_security_context():
    """Arrange things such that we can read or write part of the data
    in a demo license, which is stored encrypted.

    We need to re-invoke `allocate_security_module()` here, in
    spite of the fact that this has already been done in `create_app()`,
    because it uses `request_context` to hold the result. Since
    `request_context` is part of the `flask.g` application context, and
    the application context here is different from the one used while
    finding an HSM connection in `create_app()`, that result is gone now
    and we need to call the function again.
    """

    set_config()  # ensure `request_context` exists
    allocate_security_module()


# ------------------------------------------------------------------------- --
# Command `linotp support set --file support_file`
# ------------------------------------------------------------------------- --


@support_cmds.command("set", help="set linotp support via linotp cli.")
@click.argument("license_file_name")
@with_appcontext
def set_support(license_file_name):
    """set a linotp support similar to system/setSupport."""

    try:

        _setup_security_context()

        with open(license_file_name, "rb") as license_file:
            license_text = license_file.read()

        session = db.session()

        success, status = setSupportLicense(license_text.decode("utf-8"))

        session.commit()

    except Exception as exx:
        current_app.echo(f"Setting license could not be completed: {exx}")
        sys.exit(1)

    if not success:
        current_app.echo(f"Failed to set license! {status}")
        sys.exit(2)

    current_app.echo("Successfully set license.")
    sys.exit(0)


# ------------------------------------------------------------------------- --
# Command `linotp support get`
# ------------------------------------------------------------------------- --


@support_cmds.command("get", help=("get linotp support info."))
@with_appcontext
def get_support():
    """get the linotp support info similar to system/getSupportInfo"""

    try:

        _setup_security_context()

        session = db.session()

        license_dict, license_signature = getSupportLicenseInfo()

        session.close()

    except Exception as exx:
        current_app.echo(f"Getting support could not be completed: {exx}")
        sys.exit(1)

    if not license_dict:
        if isinstance(license_dict, dict):
            current_app.echo("No support license installed")
        else:
            current_app.echo("Getting support failed!")
        sys.exit(2)

    print(json.dumps(license_dict, indent=4, sort_keys=True))
    sys.exit(0)


# ------------------------------------------------------------------------- --
# Command `linotp support valid`
# ------------------------------------------------------------------------- --


@support_cmds.command("verify", help=("is linotp support valid."))
@click.option(
    "--filename",
    "-f",
    type=click.Path(exists=True),
    help=("license file, which is validated against a current linotp"),
)
@with_appcontext
def is_support_valid(filename):
    """checks if the linotp support info is valid similar to isSupportValid"""

    try:

        _setup_security_context()

        session = db.session()

        if filename:

            with open(filename, "rb") as license_file:
                license_text = license_file.read()

            license_text = license_text.decode("utf-8").replace("\n", "\n")
            license_dict, license_signature = parseSupportLicense(license_text)
        else:

            license_dict, license_signature = getSupportLicenseInfo()

        valid = isSupportLicenseValid(
            lic_dict=license_dict,
            lic_sign=license_signature,
            raiseException=True,
        )

        session.close()

    except InvalidLicenseException as exx:
        current_app.echo(f"Invalid License: {exx}")
        sys.exit(2)

    except Exception as exx:
        current_app.echo(f"Validating support could not be completed: {exx}")
        sys.exit(1)

    if not license_dict:
        if isinstance(license_dict, dict):
            current_app.echo("No support license installed")
        else:
            current_app.echo("Validating support failed!")
        sys.exit(2)

    if not valid or not isinstance(valid, tuple):
        current_app.echo("Validating support error: %r" % valid)
        sys.exit(2)

    print(valid[0])
    sys.exit(0)
