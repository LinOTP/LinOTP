# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2019 KeyIdentity GmbH
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
#

"""
test to verify that the linotp cli for backup and restore
of linotp audit and database works

the test does not cover restore_legacy as this could only be verified
against a mysql database which could not be used in a unit test
"""

import pytest
from datetime import datetime
from pathlib import Path

from linotp.cli import main as cli_main


@pytest.fixture
def runner(app):
    """Set common configuration """

    env = {
        'LINOTP_AUDIT_DATABASE_URI': 'SHARED',
    }
    return app.test_cli_runner(env=env, mix_stderr=False, echo_stdin=True)


def test_database(app, runner, freezer):
    """ verify that database backup and restore are working

    - create a backup
    - list the available backup
    - restore the backup by date or file or absolute filename
    """

    freezer.move_to("2020-08-18 19:25:33")
    str_now = datetime.now().strftime(app.config["BACKUP_FILE_TIME_FORMAT"])

    # Create a database backup
    print("Invoke 'backup create'")
    result = runner.invoke(cli_main, ['-v', 'backup', 'create'])
    assert result.exit_code == 0

    # check that the backup directory was created
    backup_dir = Path(app.config["BACKUP_DIR"])
    assert backup_dir.is_dir()

    backup_file = backup_dir / f"linotp_backup_{str_now}.sqldb"
    assert backup_file.is_file()

    assert 'Config' in backup_file.read_text()

    # list database backups
    result = runner.invoke(cli_main, ['backup', 'list'])
    assert str_now in result.output


@pytest.mark.parametrize("args,result", [
    (['--date', 'NOW'], 0),
    (['--file', 'linotp_backup_NOW.sqldb'], 0),
    (['--date', 'NOW', '--table', 'Config'], 0),
    (['--date', 'NOW', '--table', 'Foo'], 1),
])
def test_backup_restore_cmd(app, runner, freezer, args, result):
    freezer.move_to("2020-08-18 19:25:33")
    str_now = datetime.now().strftime(app.config["BACKUP_FILE_TIME_FORMAT"])

    backup_result = runner.invoke(cli_main, ['backup', 'create'])
    assert backup_result.exit_code == 0

    args = [a.replace('NOW', str_now) for a in args]
    cmd_result = runner.invoke(cli_main, ['backup', 'restore'] + args)
    assert cmd_result.exit_code == result
