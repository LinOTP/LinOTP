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
"""
Tests the logging decorators
"""

import unittest
from datetime import datetime, timedelta

from freezegun import freeze_time

from linotp.tokens.base.validity_mixin import TokenValidityMixin


class FakeTokenInfoMixin(object):
    def __init__(self):
        self.info = {}

    def getTokenInfo(self):
        return self.info

    def setTokenInfo(self, info):
        self.info = info

    def addToTokenInfo(self, key, value):
        self.info[key] = value

    def getFromTokenInfo(self, key, default=None):
        return self.info.get(key, default)

    def removeFromTokenInfo(self, key):
        if key in self.info:
            del self.info[key]


class FakeTokenClass(FakeTokenInfoMixin, TokenValidityMixin):
    pass


class TestTokenValidityMixin(unittest.TestCase):
    """
    Unit tests for token validity checks
    """

    def test_access_count(self):
        """
        check if the access counter (with getter and setter) is incremented
        """

        fake_token = FakeTokenClass()

        fake_token.count_auth_max = 3

        for _i in range(1, 10):

            fake_token.count_auth = fake_token.count_auth + 1

            if fake_token.count_auth >= fake_token.count_auth_max:
                assert fake_token.has_exceeded_usage()
                break
            else:
                assert not fake_token.has_exceeded_usage()

        assert fake_token.count_auth == 3, fake_token

        return

    def test_del_access_count(self):
        """
        check that the max access counter will be removed
        """

        fake_token = FakeTokenClass()

        fake_token.count_auth_max = 3

        assert fake_token.count_auth_max == 3, fake_token

        fake_token.del_count_auth_max()

        t_info = fake_token.getTokenInfo()

        assert "count_auth_max" not in t_info, fake_token

        return

    def test_inc_access_count(self):
        """
        check if the access counter (with getter and setter) is incremented
        """

        fake_token = FakeTokenClass()

        fake_token.count_auth_max = 3

        for _i in range(1, 10):

            fake_token.inc_count_auth()

            if fake_token.count_auth > fake_token.count_auth_max:
                break

        assert fake_token.count_auth == 4, fake_token

        return

    # ---------------------------------------------------------------------- --

    def test_success_count(self):
        """
        check if the success counter (with getter and setter) is incremented
        """

        fake_token = FakeTokenClass()

        fake_token.count_auth_success_max = 3

        for _i in range(1, 10):

            fake_token.count_auth_success = fake_token.count_auth_success + 1

            if (
                fake_token.count_auth_success
                >= fake_token.count_auth_success_max
            ):
                assert fake_token.has_exceeded_success()
                break
            else:
                assert not fake_token.has_exceeded_success()

        assert fake_token.count_auth_success == 3, fake_token

        return

    def test_inc_success_count(self):
        """
        check if the success counter (with getter and setter) is incremented
        """

        fake_token = FakeTokenClass()

        fake_token.count_auth_success_max = 3
        for _i in range(1, 10):
            fake_token.inc_count_auth_success()
            if (
                fake_token.count_auth_success
                > fake_token.count_auth_success_max
            ):
                break

        assert fake_token.count_auth_success == 4, fake_token

        return

    def test_del_success_count(self):
        """
        delete the success counter
        """

        fake_token = FakeTokenClass()

        fake_token.count_auth_success_max = 3

        assert fake_token.count_auth_success_max == 3, fake_token

        fake_token.del_count_auth_success_max()

        t_info = fake_token.getTokenInfo()

        assert "count_auth_success_max" not in t_info, fake_token

    # ---------------------------------------------------------------------- --

    def test_del_expiry_end(self):
        """
        check expiration end compare
        """

        fake_token = FakeTokenClass()

        now = datetime.now()
        end_time = now - timedelta(minutes=1)

        end_time_str = datetime.strftime(end_time, "%d/%m/%y %H:%M")
        fake_token.validity_period_end = end_time_str

        assert fake_token.validity_period_end, fake_token

        fake_token.del_validity_period_end()

        t_info = fake_token.getTokenInfo()

        assert "validity_period_end" not in t_info, fake_token

        return

    def test_del_expiry_start(self):
        """
        check expiration end compare
        """

        fake_token = FakeTokenClass()

        now = datetime.now()
        start_time = now - timedelta(minutes=1)

        start_time_str = datetime.strftime(start_time, "%d/%m/%y %H:%M")
        fake_token.validity_period_start = start_time_str

        assert fake_token.validity_period_start, fake_token

        fake_token.del_validity_period_start()

        t_info = fake_token.getTokenInfo()

        assert "validity_period_start" not in t_info, fake_token

        return

    # ---------------------------------------------------------------------- --

    def test_for_expiry_end(self):
        """
        check expiration end compare
        """

        fake_token = FakeTokenClass()
        assert (
            not fake_token.is_expired()
        ), "the token should not be expired as no expiration time set"

        current_time = datetime(year=2020, month=2, day=2, hour=2, minute=2)
        expiration_time = current_time + timedelta(hours=1)

        fake_token.validity_period_end = expiration_time.strftime(
            "%d/%m/%y %H:%M"
        )

        with freeze_time(current_time, tz_offset=5) as frozen_time:

            assert (
                not fake_token.is_expired()
            ), "the token should not be expired as current time before expiration"
            frozen_time.tick(delta=timedelta(hours=1, minutes=1))
            assert (
                fake_token.is_expired()
            ), "the token should be expired as current time after expiration"

    def test_for_expiry_start(self):
        """
        check expiration start compare
        """

        fake_token = FakeTokenClass()

        assert (
            not fake_token.is_not_yet_valid()
        ), "the token should be valid as no validity start time set"

        current_time = datetime(year=2020, month=2, day=2, hour=2, minute=2)
        activation_time = current_time + timedelta(hours=1)

        fake_token.validity_period_start = activation_time.strftime(
            "%d/%m/%y %H:%M"
        )

        with freeze_time(current_time, tz_offset=5) as frozen_time:

            assert (
                fake_token.is_not_yet_valid()
            ), "the token should not be valid as current time before validity start time"
            frozen_time.tick(delta=timedelta(hours=1, minutes=1))
            assert (
                not fake_token.is_not_yet_valid()
            ), "the token should be valid as current time after validity start time"


# eof #
