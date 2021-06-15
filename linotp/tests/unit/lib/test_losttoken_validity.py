# -*- coding: utf-8 -*-
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
Tests the chunked data handling in the config
"""

import unittest
import datetime

from mock import patch

from linotp.lib.token import _calculate_validity_end


class LostTokenValidityTest(unittest.TestCase):
    @patch("linotp.lib.policy.get_action_value")
    def test_validty_end_in_5_days(self, patch_get_action_value):
        """
        test the backward compatibilty case where the policy returns an int
        """

        end_date = _calculate_validity_end(validity=5)

        assert "23:59" in end_date

        in_five_days = (
            datetime.date.today() + datetime.timedelta(days=5)
        ).strftime("%d/%m/%y")

        assert in_five_days in end_date

        return

    @patch("linotp.lib.policy.get_action_value")
    def test_validty_w_duration(self, patch_get_action_value):
        """
        test the simple duration expression
        """

        end_date = _calculate_validity_end(" 1 H ")

        in_one_hour = (
            datetime.datetime.now() + datetime.timedelta(hours=1)
        ).strftime("%d/%m/%y %H")

        assert in_one_hour in end_date

        return

    @patch("linotp.lib.policy.get_action_value")
    def test_validty_w_duration_expr(self, patch_get_action_value):
        """
        test the complex duration expression
        """

        validity = "1d 1 h"

        end_date = _calculate_validity_end(validity)

        in_one_hour = (
            datetime.datetime.now() + datetime.timedelta(days=1, hours=1)
        ).strftime("%d/%m/%y %H")

        assert in_one_hour in end_date

        return

    @patch("linotp.lib.policy.get_action_value")
    def test_validty_w_duration_expr2(self, patch_get_action_value):
        """
        test the complex duration expression
        """

        validity = "36 h 120 m"

        end_date = _calculate_validity_end(validity)

        in_one_hour = (
            datetime.datetime.now() + datetime.timedelta(hours=36, minutes=120)
        ).strftime("%d/%m/%y %H")

        assert in_one_hour in end_date

        return


# eof #
