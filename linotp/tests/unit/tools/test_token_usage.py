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
import mock

from .script_testing_lib import ScriptTester

# -------------------------------------------------------------------------- --

class TestLinotpTokenUsage(ScriptTester):

    script_name = 'linotp-token-usage'

    @pytest.mark.xfail(reason="old-style INI-based configuration")
    @mock.patch('linotp_token_usage.token_usage')
    @mock.patch('sys.exit')
    def test_main(self, mock_exit, mock_usage):
        self.script_module.main()
        mock_usage.assert_called_once()

    @pytest.mark.xfail(reason="old-style INI-based configuration")
    def test_token_usage(self):
        self.script_module.token_usage(None, None, '')
