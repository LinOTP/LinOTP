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
Test lib challenge methods
"""

import unittest
from mock import patch
from linotp.lib.challenges import Challenges
import pytest


@pytest.mark.usefixtures("app")
class TestChallengesTransactionidLength(unittest.TestCase):

    def test_transactionid_length(self):

        with patch('linotp.lib.challenges.context') as mock_context:
            mock_context.get.return_value = {}
            transid_length = Challenges.get_tranactionid_length()
            assert round(abs(transid_length-Challenges.DefaultTransactionIdLength), 7) == 0

            too_short_length = 7

            wrong_range_message = \
                "TransactionIdLength must be between 12 and 17, " \
                "was %d" % too_short_length
            mock_context.get.return_value = {
                'TransactionIdLength': too_short_length
            }
            with pytest.raises(Exception) as wrong_range:
                Challenges.get_tranactionid_length()

            assert str(wrong_range.value) == wrong_range_message
