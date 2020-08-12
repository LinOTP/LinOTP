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

import pytest
import os
import freezegun
from datetime import datetime

from click.testing import CliRunner
from linotp.cli.backup_cmd import (
    create_command,
    list_command,
    restore_command,
    )

from linotp.cli.backup_cmd import TIME_FORMAT

class TestInitBackupRestore:
    """
    test to verify that the linotp cli for backup and restore
    of linotp audit and database works

    the test does not cover restore_legacy as this could only be verified
    against a mysql database which could not be used in a unit test
    """

    @pytest.fixture(autouse=True)
    def runner(self, tmp_path):
        """Set common configuration """

        sqlite_db = os.path.join(str(tmp_path), 'sqlite.db')
        env = {
            'FLASK_APP': 'linotp.app', 
            'LINOTP_ROOT_DIR': str(tmp_path),
            'LINOTP_BACKUP_DIR': 'backups',
            'LINOTP_AUDIT_DATABASE_URI': 'SHARED',
            'LINOTP_SQLALCHEMY_DATABASE_URI':
                    'sqlite:///{}'.format(sqlite_db),
            'DB_FILE': sqlite_db
        }
        self.runner = CliRunner(env=env, mix_stderr=False, echo_stdin=True)


    def test_database(self, tmp_path):
        """ verify that database backup and restore are working

        - create a backup
        - list the available backup
        - restore the backup by date or file or absolute filename
        """

        now = datetime.now()
        str_now = now.strftime(TIME_FORMAT)

        with freezegun.freeze_time(now):

            # Create a database backup
            result = self.runner.invoke(create_command, [])
            assert result.exit_code == 0
    
            # check that the backup directory was created
            backup_dir = os.path.join(str(tmp_path), 'backups')

            assert os.path.isdir(backup_dir)

            backup_file = os.path.join(
                backup_dir, f"linotp_backup_{str_now}.sqldb")

            assert os.path.isfile(backup_file)

            with open(backup_file, 'r') as f:
                content = f.read()
                assert 'Config' in content

        # list database backups
        result = self.runner.invoke(list_command, [])
        assert str_now in result.output

        # restore backup by date
        result = self.runner.invoke(restore_command, ['--date', str_now])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(
            restore_command, ['--file', f"linotp_backup_{str_now}.sqldb"])
        assert result.exit_code == 0

        # restore backup by absolute file
        result = self.runner.invoke(restore_command, ['--file', backup_file])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(restore_command,
                                    ['--date', str_now, '--table', 'Config'])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(restore_command,
                                    ['--date', str_now, '--table', 'Foo'])
        assert result.exit_code == 1

        return

