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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com

"""Entry point for LinOTP CLI.

The `main()` function in this file is installed as a console entry point
in `setup.py()`, so that the shell command `linotp` calls that function.
We use this to ensure that Flask is initialised with the correct value
for `FLASK_APP`.

"""

import os
import click
import sys

from subprocess import call

from datetime import datetime
from flask import current_app

from flask.cli import main as flask_main
from flask.cli import with_appcontext
from flask.cli import AppGroup
from flask.cli import FlaskGroup

from linotp.app import create_app

FLASK_APP_DEFAULT = "linotp.app"   # Contains default `create_app()` factory
FLASK_ENV_DEFAULT = "development"  # Default Flask environment, for debugging


def main():
    """Main CLI entry point for LinOTP. All the heavy lifting is delegated
    to Flask.
    """
    os.environ["FLASK_APP"] = FLASK_APP_DEFAULT
    if "FLASK_ENV" not in os.environ:
        os.environ["FLASK_ENV"] = FLASK_ENV_DEFAULT
    flask_main()

backup_cmds = AppGroup('backup')


backup_cmds = AppGroup('backup')
