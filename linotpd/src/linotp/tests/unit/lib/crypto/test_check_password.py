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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""

"""

import unittest

from linotp.lib.crypto import SecretObj
from linotp.lib.crypto import libcrypt_password

class TestComparePassword(unittest.TestCase):
    """
    unit test to verify the new password comparison in secret object
    """

    def test_compare_password(self):
        """
        test the new compare passwords - used in the pw and lost token
        """

        # init the SecretObject

        sec_obj = SecretObj(val=libcrypt_password('password'), iv=':1:')

        # run the comparison tests - positive test

        res = sec_obj.compare_password('password')
        self.assertTrue(res)

        # negative test

        res = sec_obj.compare_password('Password')
        self.assertFalse(res)

        return

# eof #

