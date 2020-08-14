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
import os
from os.path import join

from sqlalchemy import *

import pytest
from mock import patch


from click.testing import CliRunner
from linotp.cli.audit_cmd import cleanup_command
from .script_testing_lib import ScriptTester

# -------------------------------------------------------------------------- --

AUDIT_AMOUNT_ENTRIES = 100

class TestAuditJanitor:

    @pytest.fixture
    def setup_audit_table(self, app):
        """Add AUDIT_AMOUNT_ENTRIES entries into the fresh audit database"""

        entry = {
            'action' : 'validate/check',
        }
        for count in range(AUDIT_AMOUNT_ENTRIES):
            app.audit_obj.log_entry(entry)


    @pytest.fixture(autouse=True)
    def runner(self, app, tmp_path):
        """Set common configuration 
        
        Note: LINOTP_SQLALCHEMY_DATABASE_URI and LINOTP_DATABASE_URL have to
        set. Otherwise the created database (sqlite) from conftest.py would
        not be used. This env and CLIRunner would create a second database.
        But if the runner is invoked the database from conftest.py will be used
        (due to flask.current_app) which differs from this in this test
        (tmp_path...). Therefore we pass the app.audit_obj.engine.url into
        env['LINOTP_SQLALCHEMY_DATABASE_URI'] and env['LINOTP_DATABASE_URL']
        so we have the same database for the setup of the test (where 
        AUDIT_AMOUNT_ENTRIES entries will be generated) and executing
        `linotp audit-janitor` command
        """
        sqlite_db = os.path.join(str(tmp_path), 'sqlite.db')
        env = {
            'FLASK_APP': 'linotp.app', 
            'LINOTP_ROOT_DIR': str(tmp_path),
            'LINOTP_AUDIT_DATABASE_URI': 'SHARED',
            'LINOTP_SQLALCHEMY_DATABASE_URI':
                    str(app.audit_obj.engine.url),
            'LINOTP_DATABASE_URL':
                    str(app.audit_obj.engine.url),
            }
        self.runner = CliRunner(env=env, mix_stderr=False)
        self.export_dir = tmp_path


    def test_run_janitor(self, app, setup_audit_table):
        """Run janiter with default values

        By default the max entries value is 10000 and the min value entry is
        set to 5000. Because no export directory is given, no export are
        made.
        """

        # run linotp audit-janitor
        result = self.runner.invoke(cleanup_command, [])
        assert result.exit_code == 0

    def test_run_janitor_with_params(self, app, setup_audit_table):
        """Run janitor with different max, min and export directory
      
        Max = 10, Min = 5. Prepared Database with AUDIT_AMOUNT_ENTRIES entries.
        5 entries left and AUDIT_AMOUNT_ENTRIES - min exported.
        """
        max = 10
        min = 5

        # run linotp audit-janitor --max 10 --min 5
        result = self.runner.invoke(cleanup_command, [
            '--max', max,
            '--min', min,
            '--exportdir', self.export_dir,
            ])
        assert result.exit_code == 0

        list_of_files =  os.listdir(self.export_dir)
        export_file = None
        for f in list_of_files:
            if 'SQLData' in f:
                export_file = os.path.join(self.export_dir, f)
                break

        
        assert export_file != None
        num_lines = sum(1 for line in open(export_file))
        assert num_lines == AUDIT_AMOUNT_ENTRIES - min

    def test_run_janitor_max_min(self, app, setup_audit_table):
        """Run janiter with max not greater than min"""
        max = 5
        min = 5
        # run linotp audit-janitor
        result = self.runner.invoke(cleanup_command, [
            '--max', max,
            '--min', min,
        ])
        assert result.exit_code == 1