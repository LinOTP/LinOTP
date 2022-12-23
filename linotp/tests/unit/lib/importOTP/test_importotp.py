# -*- coding: utf-8 -*-
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

from linotp.lib.ImportOTP.oath import parseOATHcsv


class TestCacheActivation(unittest.TestCase):
    def setUp(self):
        """
        we use the setUp to define the fixture path, which points to the
        location of the fixed data files
        """

        this_file = os.path.dirname(os.path.realpath(__file__))
        location, _sep, _skip = this_file.rpartition("tests" + os.sep + "unit")

        self.fixture_path = os.path.join(
            location, "tests", "functional", "fixtures"
        )

        unittest.TestCase.setUp(self)

    def _get_file_name(self, data_file):
        """
        helper to read token data files
        """
        return os.path.join(self.fixture_path, data_file)

    def _read_data(self, data_file):
        """
        helper to read token data files
        """

        file_name = self._get_file_name(data_file)

        with open(file_name, "r") as data_file:

            data = data_file.read()

            return data

    def test_parse_OATH(self):
        """
        Test the OATH csv import for sha1 totp and hmac tokens
        """
        csv = self._read_data("oath_tokens.csv")

        TOKENS = parseOATHcsv(csv)

        assert len(TOKENS) == 4, TOKENS

        assert TOKENS["tok4"].get("timeStep") == 60, TOKENS

        assert TOKENS["tok3"].get("otplen") == 8, TOKENS

        return

    def test_parse_OATH_256(self):
        """
        Test the OATH csv import for sha256 tokens
        """
        csv = self._read_data("oath_tokens_sha256.csv")

        tokens = parseOATHcsv(csv)

        assert len(tokens) == 8, tokens

        for serial, token in list(tokens.items()):
            if "sha256" in serial:
                assert token["hashlib"] == "sha256", token

        return


# eof #
