# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#

from mock import patch

from script_testing_lib import ScriptTester

# -------------------------------------------------------------------------- --

class TestLinotpTokenUsage(ScriptTester):

    script_name = 'linotp-sql-janitor'

    @patch('os.path.isfile')
    @patch('logging.FileHandler')
    @patch('sys.exit')
    def test_main(self, mock_exit, mock_log, mock_isfile):
        with patch('sys.argv', ['']):
            self.script_module.main()
        mock_exit.assert_called_with(0)

    def test_usage(self):
        self.script_module.usage()
