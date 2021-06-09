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
from mock import patch

from .script_testing_lib import ScriptTester

# -------------------------------------------------------------------------- --


class TestLinotpTokensUsed(ScriptTester):

    script_name = "linotp-tokens-used"

    def run_main(self, *args):
        main_args = [self.script_module.__name__]
        main_args.extend(args)

        with patch("sys.argv", main_args):

            output = []

            def append_output(print_args):
                output.append(str(print_args))

            with patch.object(
                self.script_module, "print", side_effect=append_output
            ):
                with patch("sys.exit"):
                    self.script_module.main()

    @pytest.mark.xfail(reason="old-style INI-based configuration")
    def test_main_config(self):
        with patch.object(
            self.script_module,
            "print_config",
            wraps=self.script_module.print_config,
        ) as mock_config:
            self.run_main("config")
            mock_config.assert_called_with()

    @pytest.mark.xfail(reason="old-style INI-based configuration")
    @patch("sys.exit")
    def test_config(self, mock_exit):
        with patch.object(self.script_module, "print_config") as mock_config:
            self.script_module.main()

    @pytest.mark.xfail(reason="old-style INI-based configuration")
    def test_token_usage(self):
        self.script_module.tokens_used(None)
