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

"""Entry point for LinOTP CLI.

The `main()` function in this file is installed as a console entry point
in `setup.py()`, so that the shell command `linotp` calls that function.
"""

import logging
import os
import sys
from datetime import datetime

import click
from flask import Flask, current_app
from flask.cli import FlaskGroup, with_appcontext

from linotp.app import create_app
from linotp.settings import LinOTPConfigValueError


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
        self._configure_logging()

    def _configure_logging(self):
        """Configure logging level based on verbosity for CLI commands only."""
        log_levels = {
            -1: logging.CRITICAL,  # -q
            0: logging.ERROR,  # default
            1: logging.WARNING,  # -v
            2: logging.INFO,  # -vv
            3: logging.DEBUG,  # -vvv
        }
        log_level = log_levels.get(self.verbosity, logging.DEBUG)
        linotp_logger = logging.getLogger(__name__)
        linotp_logger.setLevel(log_level)

    def __call__(self, message, **kwargs):
        """Make instance of echo callable like a function.

        This is our equivalent to `click.echo()`, except that we take
        an additional `v` or `verbosity` parameter (which defaults to `0`),
        and `err` defaults to `True`.
        """

        verbosity = kwargs.pop("v", kwargs.pop("verbosity", 0))
        if verbosity <= self.verbosity:
            err = kwargs.pop("err", True)
            click.echo(message, err=err, **kwargs)


def get_backup_filename(filename: str, now: datetime | None = None) -> str:
    """
    Creates a time-stamped filename suitable for use as a “backup
    filename”. The given filename can contain a placeholder `%s` where
    the timestamp should be put. If no placeholder is found, the time
    stamp is appended, separated with `.`.

    The time used is given as `now`; if `now` is `None`, the current
    time will be used. The time stamp is formatted as configured by
    "BACKUP_FILE_TIME_FORMAT" config value.
    """
    now = now or datetime.now()
    ext = now.strftime(current_app.config["BACKUP_FILE_TIME_FORMAT"])

    if "%s" in filename:
        return filename.replace("%s", ext)
    else:
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
        # Check if --help is in the arguments to avoid app initialization
        if "--help" in sys.argv:

            def minimal_app():
                """Create a minimal Flask app just for displaying help."""
                app = Flask("linotp_help")
                return app

            kwargs["create_app"] = minimal_app

        super().__init__(add_version_option=False, **kwargs)
        for arg in sys.argv[1:]:
            if arg[0] != "-":
                os.environ["LINOTP_CMD"] = arg
                break


def make_create_app():
    def factory():
        config_name = os.getenv("LINOTP_CONFIG", "default")
        try:
            return create_app(config_name)
        except LinOTPConfigValueError as e:
            click.echo("Failed to initialize app configuration", err=True)
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    return factory


# Main command group for the application. Here's where we end up when
# the user gives the `linotp` command on the command line. We rely on
# Click to dispatch to subcommands in their respective groups. Note that
# new subcommands (or subcommand groups) must be registered in `setup.py`
# to become reachable.


@click.version_option(message="LinOTP %(version)s")
@click.group(name="linotp", cls=LinOTPGroup, create_app=make_create_app())
@click.option(
    "--verbose",
    "-v",
    count=True,
    help=(
        "Increase amount of output from the command (can be specified several times)."
    ),
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help=("Don't generate any output at all (check exit code for success/failure)."),
)
@with_appcontext
def main(verbose, quiet):
    current_app.echo = Echo(-1 if quiet else verbose)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
