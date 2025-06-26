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

"""
tests for the type utils (IP address dotted quad syntax checker)
"""

import pytest

from linotp.lib.type_utils import is_ip_address_dotted_quad


@pytest.mark.parametrize(
    "address,result",
    [
        ("", False),
        ("foobar", False),
        ("1", False),
        ("1.2", False),
        ("1.2.3", False),
        ("1.2.3.4", True),
        ("1.2.3.4.5", False),
        ("111.222.333.444", False),
    ],
)
def test_is_ip_address_dotted_quad(address, result):
    assert is_ip_address_dotted_quad(address) is result
