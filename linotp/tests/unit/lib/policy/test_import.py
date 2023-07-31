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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

""" unit test policy import """

import unittest

from configobj import ConfigObj
from mock import patch

from linotp.lib.policy.manage import import_policies


class TestImportPolicy(unittest.TestCase):
    """"""

    @patch("linotp.lib.policy.manage.setPolicy")
    def test_import_policy(self, mocked_setPolicy):
        """
        test the import of policies with empty or no existing realm
        """

        return_value = {
            "realm": True,
            "active": True,
            "client": True,
            "user": True,
            "time": True,
            "action": True,
            "scope": True,
        }

        mocked_setPolicy.return_value = return_value

        # ------------------------------------------------------------------ --

        # test with empty realm in the input data

        fileString = """[empty_realm]
realm = ""
active = True
client = ""
user = *
time = ""
action = "otppin=password "
scope = authentication
"""

        policies_config = ConfigObj(fileString.split("\n"), encoding="UTF-8")

        _result = import_policies(policies_config)

        args, _kwargs = mocked_setPolicy.call_args
        policy = args[0]
        assert policy["realm"] == "*"

        # ------------------------------------------------------------------ --

        # test with no realm in the input data

        fileString2 = """[no_realm]
active = True
client = ""
user = *
time = ""
action = "otppin=password "
scope = authentication

"""

        policies_config = ConfigObj(fileString2.split("\n"), encoding="UTF-8")

        _result = import_policies(policies_config)

        args, _kwargs = mocked_setPolicy.call_args
        policy = args[0]
        assert policy["realm"] == "*"

        return


# eof #
