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
import stat
from click.testing import CliRunner
from linotp.cli import init_enc_key
from linotp.lib.tools.enckey import create_secret_key
import linotp.lib.tools.enckey as enckey


class TestInitEncKey:
    @pytest.fixture(autouse=True)
    def runner(self, tmp_path):
        """Set common configuration """
        self.secret_file = tmp_path / 'encKey'
        env = {'FLASK_APP': 'linotp.app', 'LINOTP_ROOT_DIR': str(tmp_path),
               'LINOTP_SECRET_FILE': str(self.secret_file)}
        self.runner = CliRunner(env=env, mix_stderr=False)


    def test_file_not_exists(self):
        """No secret file exist.

        We are creating a new one.
        """
        # Check that no file exists
        assert not self.secret_file.exists()

        # Create secret file
        result = self.runner.invoke(init_enc_key, [])
        assert result.exit_code == 0
        # check that secret file exists
        assert self.secret_file.exists()


    def test_file_exists_no_overwrite(self):
        """Secret file exists already and we do not want to overwrite it

        Force overwrite is not enabeld => File should not be overwritten
        """
        if not self.secret_file.exists():
            result = self.runner.invoke(init_enc_key, [])
            assert result.exit_code == 0
            

        # Check that file exists
        assert self.secret_file.exists()
        # load secret from file to compare afterwards
        with open(self.secret_file, 'rb') as f:
            secret = f.read()

        # Try to create secret file
        result = self.runner.invoke(init_enc_key, [])
        assert result.exit_code == 0
        
        # secret file stays the same as before
        with open(self.secret_file, 'rb') as f:
            secret_2 = f.read()
        assert secret == secret_2


    def test_file_exists_and_overwrite(self):
        """Secret file exists already and we want to overwrite it

        Force overwrite is enabeld => File should be overwritten
        """
        if not self.secret_file.exists():
            result = self.runner.invoke(init_enc_key, [])
            assert result.exit_code == 0
         
        # Check that file exists
        assert self.secret_file.exists()
        # load secret from file to compare afterwards
        with open(self.secret_file, 'rb') as f:
            secret = f.read()

        # Try to create secret file
        # Try to create secret file
        result = self.runner.invoke(init_enc_key, ['--force'])
        assert result.exit_code == 0
        # secret file stays the same as before
        with open(self.secret_file, 'rb') as f:
            secret_2 = f.read()
        assert secret != secret_2


    def test_key_file_content(self):
        """Test created secret file content

        Check the created file contain enckey.KEY_COUNT keys of length
        enckey.KEY_LENGTH byte
        """
        if not self.secret_file.exists():
            result = self.runner.invoke(init_enc_key, [])
            assert result.exit_code == 0

        assert self.secret_file.exists()
        with open(self.secret_file, 'rb') as f:
            # get 3 keys out with 32
            # the 4th try to get a key should be 0
            for count in range(enckey.KEY_COUNT + 1):
                key = f.read(enckey.KEY_LENGTH)

                if count >= enckey.KEY_COUNT:
                    # at KEY_COUNT +1 iteration the key should be empty
                    assert len(key) == 0
                else:
                    assert len(key) == enckey.KEY_LENGTH


    def test_file_access(self):
        """Test file is only readable by the owner (400)"""

        if not self.secret_file.exists():
            result = self.runner.invoke(init_enc_key, [])
            assert result.exit_code == 0
        secret_key_file_permissions = stat.S_IMODE(self.secret_file.stat().st_mode)
        assert secret_key_file_permissions == enckey.SECRET_FILE_PERMISSIONS
