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

from linotp.lib.crypto import SecretObj, utils


def test_compare_password():
    """
    test to verify the new password comparison in secret object
    used in the pw and lost token.
    """

    # init the SecretObject

    enc_password = utils.crypt_password("password").encode("utf-8")
    sec_obj = SecretObj(val=enc_password, iv=b":1:")

    # run the comparison tests - positive test

    res = sec_obj.compare_password("password")
    assert res

    # negative test

    res = sec_obj.compare_password("Password")
    assert not res
