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
#

import os
import unittest

import pytest

from linotp.provider.config_parsing import ConfigParsingMixin
from linotp.tests import TestController


class TestProviderBase(unittest.TestCase):
    """ """

    def test_server_certificate_policy_default(self):
        """verify if no parameter is given - result is None"""

        configurations = [
            {},
            {"server_certificate": None},
            {"server_certificate": ""},
        ]

        for config in configurations:
            res = ConfigParsingMixin.load_server_cert(
                config, server_cert_key="server_certificate"
            )

            assert res is None

    def test_server_certificate_policy_ValueError(self):
        """verify parameter is not string or False, a Value error is raised"""

        configurations = [
            {"server_certificate": 22},
            {"server_certificate": b"deadbeaf"},
            {"server_certificate": True},
        ]

        for config in configurations:
            with pytest.raises(ValueError):
                _res = ConfigParsingMixin.load_server_cert(
                    config, server_cert_key="server_certificate"
                )

    def test_server_certificate_policy_false(self):
        """no verify if the result is False"""
        configurations = [
            {"server_certificate": "false"},
            {"server_certificate": False},
            {"server_certificate": "False"},
            {"server_certificate": "fAlse"},
        ]

        for config in configurations:
            res = ConfigParsingMixin.load_server_cert(
                config, server_cert_key="server_certificate"
            )

            assert res is False

    def test_server_certificate_policy_file(self):
        """use certificate for verification"""

        config = {
            "server_certificate": os.path.join(TestController.fixture_path, "cert.pem")
        }

        res = ConfigParsingMixin.load_server_cert(
            config, server_cert_key="server_certificate"
        )

        assert isinstance(res, bytes)
        assert res.decode("utf8") == config["server_certificate"]

    def test_server_certificate_policy_file_error(self):
        """use certificate for verification - which raises an IOError"""

        config = {
            "server_certificate": os.path.join(
                TestController.fixture_path, "file_does_not_exist"
            )
        }

        with pytest.raises(IOError):
            _res = ConfigParsingMixin.load_server_cert(
                config, server_cert_key="server_certificate"
            )
