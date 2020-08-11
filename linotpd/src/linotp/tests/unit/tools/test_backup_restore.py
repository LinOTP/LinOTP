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
from linotp.cli import backup_database
from linotp.cli import restore_database
from linotp.cli import backup_audit
from linotp.cli import restore_audit


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
        self.runner = CliRunner(env=env, mix_stderr=False)


    def test_database(self, tmp_path):
        """ verify that database backup and restore are working

        - create a backup
        - list the available backup
        - restore the backup by date or file or absolute filename
        """

        now = datetime.now()
        str_now = now.strftime('%y%m%d%H%M')

        with freezegun.freeze_time(now):

            # Create a database backup
            result = self.runner.invoke(backup_database, [])
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
        result = self.runner.invoke(restore_database, ['--list'])
        assert str_now in result.output

        # restore backup by date
        result = self.runner.invoke(restore_database, ['--date', str_now])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(
            restore_database, ['--file', f"linotp_backup_{str_now}.sqldb"])
        assert result.exit_code == 0

        # restore backup by absolute file
        result = self.runner.invoke(restore_database, ['--file', backup_file])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(restore_database,
                                    ['--date', str_now, '--table', 'Config'])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(restore_database,
                                    ['--date', str_now, '--table', 'Foo'])
        assert result.exit_code == 1

        return

    def test_audit(self, tmp_path):
        """ verify that audit backup and restore are working

        - create a backup
        - list the available backup
        - restore the backup by date or file or absolute filename
        """

        now = datetime.now()
        str_now = now.strftime('%y%m%d%H%M')

        with freezegun.freeze_time(now):

            # Create a database backup
            result = self.runner.invoke(backup_audit, [])
            assert result.exit_code == 0
    
            # check that the backup directory was created
            backup_dir = os.path.join(str(tmp_path), 'backups')

            assert os.path.isdir(backup_dir)

            for backup_file in os.listdir(backup_dir):
                print(backup_file)

            backup_file = os.path.join(
                backup_dir, f"linotp_audit_backup_{str_now}.sqldb")

            assert os.path.isfile(backup_file)

            with open(backup_file, 'r') as f:
                content = f.read()
                
                assert 'Config' not in content
                assert 'AuditTable' in content

        # list database backups
        result = self.runner.invoke(restore_audit, ['--list'])
        assert str_now in result.output

        # restore backup by date
        result = self.runner.invoke(restore_audit, ['--date', str_now])
        assert result.exit_code == 0

        # restore backup by date
        result = self.runner.invoke(
            restore_audit, ['--file', f"linotp_audit_backup_{str_now}.sqldb"])
        assert result.exit_code == 0

        # restore backup by absolute file
        result = self.runner.invoke(restore_audit, ['--file', backup_file])
        assert result.exit_code == 0

        # restore audit does not support to select a table 
        result = self.runner.invoke(
            restore_audit, ['--file', backup_file, '--table', 'Audit'])
        assert result.exit_code == 2

