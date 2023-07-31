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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""

"""

import unittest
from hashlib import sha1

import pytest

from linotp.lib.crypto.utils import Hashlib_map, get_hashalgo_from_description


class TestGetHashAlgoFromDescription(unittest.TestCase):
    """
    unit test for methods to test function get_hashalgo_from_description
    """

    def test_get_invalid_hashalgo_from_descrition(self):
        """
        test to get the hash algo from different descriptions
        """

        # first test the beaking case, where description was None

        hash_algo = get_hashalgo_from_description(None)
        assert hash_algo == sha1

        # invalid hash function name but valid fallback

        hash_algo = get_hashalgo_from_description("blub")
        assert hash_algo == sha1

        # invalid hash function name and invalid fallback

        with pytest.raises(Exception) as exx:
            hash_algo = get_hashalgo_from_description("blub", fallback="blah")
        exx.match("unsupported hash function")

    def test_get_valid_hashalgo_from_descrition(self):
        """
        test to get the hash algo from different descriptions
        """

        for description, hash_function in list(Hashlib_map.items()):
            hash_algo = get_hashalgo_from_description(description)
            assert hash_algo == hash_function

        return


# eof #
