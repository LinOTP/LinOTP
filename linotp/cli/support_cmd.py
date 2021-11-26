# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2020 arxes-tolina GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com

"""linotp admin command.

linotp support set --file license_file

"""
import sys

import click

from flask import current_app
from flask.cli import AppGroup, with_appcontext

from linotp.lib.support import (
    InvalidLicenseException,
    getSupportLicenseInfo,
    isSupportLicenseValid,
    setSupportLicense,
)
from linotp.model import db

support_cmds = AppGroup(
    "support",
    help="Administrative commands to set and query the linotp support.",
)

# ------------------------------------------------------------------------- --
# Command `linotp support set --file support_file`
# ------------------------------------------------------------------------- --


@support_cmds.command("set", help="set linotp support via linotp cli.")
@click.argument("license_file_name")
@with_appcontext
def set_support(license_file_name):
    """set a linotp support similar to system/setSupport."""

    try:

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
        sys.exit(1)

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
        sys.exit(1)

    print(license_dict)
    sys.exit(0)


# ------------------------------------------------------------------------- --
# Command `linotp support valid`
# ------------------------------------------------------------------------- --


@support_cmds.command("valid", help=("is linotp support valid."))
@with_appcontext
def is_support_valid():
    """checks if the linotp support info is valid similar to isSupportValid"""

    try:
        session = db.session()

        license_dict, license_signature = getSupportLicenseInfo()

        valid = isSupportLicenseValid(
            lic_dict=license_dict,
            lic_sign=license_signature,
            raiseException=True,
        )

        session.close()

    except InvalidLicenseException as exx:
        current_app.echo(f"Invalid License: {exx}")
        sys.exit(1)

    except Exception as exx:
        current_app.echo(f"Validating support could not be completed: {exx}")
        sys.exit(1)

    if not license_dict:
        if isinstance(license_dict, dict):
            current_app.echo("No support license installed")
        else:
            current_app.echo("Validating support failed!")
        sys.exit(1)

    if not valid or not isinstance(valid, tuple):
        current_app.echo("Validating support error: %r" % valid)
        sys.exit(1)

    print(valid[0])
    sys.exit(0)
