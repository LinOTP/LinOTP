#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
Tests for EncryptedData
"""

import pytest

from linotp.lib.crypto.encrypted_data import EncryptedData

TEST_STRING = "test string to be encrypted"

# pylint:disable=redefined-outer-name
@pytest.fixture
def data():
    """
    Fixture to return an instance of encryptedData

    The unencrypted string is TEST_STRING
    """

    instance = EncryptedData(TEST_STRING)

    return instance

def test_str(data):
    """
    str() should return the string itself
    """
    assert str(data) == TEST_STRING

def test_repr(data):
    """
    repr() should return a placeholder
    """
    rep = repr(data)
    assert TEST_STRING not in rep
    assert rep == "XXXXXX"

@pytest.mark.usefixtures('hsm_obj')
def test_round_trip(app):
    orig_string = TEST_STRING

    with app.test_request_context():
        instance = EncryptedData.from_unencrypted(orig_string)
        unencrypted = instance.get_unencrypted()

        assert orig_string == unencrypted
