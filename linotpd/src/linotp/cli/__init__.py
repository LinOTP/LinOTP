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
"""

import os
import click
import sys

from subprocess import call

from flask import current_app

from flask.cli import main as flask_main
from flask.cli import with_appcontext
from flask.cli import AppGroup
from flask.cli import FlaskGroup

from linotp.app import create_app

from flask.cli import FlaskGroup
from linotp.app import create_app

FLASK_APP_DEFAULT = "linotp.app"   # Contains default `create_app()` factory
FLASK_ENV_DEFAULT = "development"  # Default Flask environment, for debugging


class Echo:
    """ Echo class, which extends the click.echo() to respect verbosity.

        The verbosity of the respective line is expressed by an
        additional parameter 'v' or 'verbosity'

        The verbosity is expressed by numbers where for suggestion:
            1 is for error and warnings
            2 is for infos
            3 is for details
            while more levels could be used

        other than click.echo, the default output will go to stderr
    """

    def __init__(self, verbosity=0):
        self.verbosity = verbosity

    def __call__(self, message, **kwargs):
        """ make instance of echo callable like a function.

            so we can wrap the click.echo with the difference of evaluating
            an verbosity parameter 'v' or 'verbosity' in the keyword arguments
        """

        verbosity = kwargs.pop('v', kwargs.pop('verbosity', 0))
        if verbosity <= self.verbosity:

            err = kwargs.pop('err', True)
            click.echo(message, err=err, **kwargs)



@click.group(cls=FlaskGroup, create_app=create_app)
@click.option('--verbose', '-v', count=True,
              help=("Increase amount of output from the command "
                    "(can be specified several times)."))
@click.option('--quiet', '-q', is_flag=True, default=False,
              help=("Don't generate any output at all (check exit "
                    "code for success/failure)."))
@with_appcontext
def main(verbose, quiet):
    current_app.echo = Echo(-1 if quiet else verbose)

backup_cmds = AppGroup('backup')

