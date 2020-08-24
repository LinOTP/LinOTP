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

from datetime import datetime
import os
import sys

import click

from flask import current_app

from flask.cli import with_appcontext
from flask.cli import FlaskGroup

from linotp.app import create_app

FLASK_APP_DEFAULT = "linotp.app"   # Contains default `create_app()` factory
FLASK_ENV_DEFAULT = "development"  # Default Flask environment, for debugging


class Echo:
    """Echo class, which extends `click.echo()` to respect verbosity.

    The verbosity of the respective line is expressed by an additional
    parameter, `v` or `verbosity`.

    The verbosity is expressed by numbers where, for example:

    - 0 is used for error messages and warnings (always displayed)
    - 1 is used for informational messages  (seen with `-v`)
    - 2 is used for more detailed information (seen with `-vv`)

    and so on. The verbosity level corresponds to the number of `-v`
    options that must be specified on the command like for the message
    to be visible. If the verbosity level is set to `-1`, no messages
    will be output at all; this is useful to implement a `--quiet`
    option that suppresses all output.

    Unlike `click.echo()`, messages go to `stderr` by default. Use
    `err=False` to redirect them to `stdout` instead.
    """

    def __init__(self, verbosity=0):
        self.verbosity = verbosity

    def __call__(self, message, **kwargs):
        """Make instance of echo callable like a function.

        This is our equivalent to `click.echo()`, except that we take
        an additional `v` or `verbosity` parameter (which defaults to `0`),
        and `err` defaults to `True`.
        """

        verbosity = kwargs.pop('v', kwargs.pop('verbosity', 0))
        if verbosity <= self.verbosity:
            err = kwargs.pop('err', True)
            click.echo(message, err=err, **kwargs)


def get_backup_filename(filename: str, now: datetime = None) -> str:
    """Given a `filename`, return a time-stamped file name suitable for
    use as a “backup filename”. The time used is given as `now`; if
    `now` is `None`, the current time will be used.
    """
    ext = (now or datetime.now()).strftime(
        current_app.config["BACKUP_FILE_TIME_FORMAT"])
    return filename + "." + ext


# Custom Click command group. We need this so we can take a peek at the
# command line prior to the initialisation of the Flask app, to see what
# sort of command we're running. That information is helpful because it
# allows us to insist that the database is properly initialised, except
# when we're doing `linotp init`.
#
# We need to do this at the earliest convenient moment (certainly before
# the `LinOTPApp` constructor is invoked) because the Flask app factory
# wants to do database initialisation. Once we end up in a Click-based
# command function it is already too late.

class LinOTPGroup(FlaskGroup):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for arg in sys.argv[1:]:
            if arg[0] != '-':
                os.environ['LINOTP_CMD'] = arg
                break


# Main command group for the application. Here's where we end up when
# the user gives the `linotp` command on the command line. We rely on
# Click to dispatch to subcommands in their respective groups. Note that
# new subcommands (or subcommand groups) must be registered in `setup.py`
# to become reachable.

@click.group(cls=LinOTPGroup, create_app=create_app)
@click.option('--verbose', '-v', count=True,
              help=("Increase amount of output from the command "
                    "(can be specified several times)."))
@click.option('--quiet', '-q', is_flag=True, default=False,
              help=("Don't generate any output at all (check exit "
                    "code for success/failure)."))
@with_appcontext
def main(verbose, quiet):
    current_app.echo = Echo(-1 if quiet else verbose)
