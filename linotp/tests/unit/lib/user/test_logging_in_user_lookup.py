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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


import unittest

from mock import patch

from linotp.lib.user import lookup_user_in_resolver

user_info = {"password": "myseecret", "username": "hugo", "userid": "123456"}


class UserLookupCache:

    cache_return_value = None

    def get_value(self, *args, **kwargs):
        return self.cache_return_value


class MockedResolverClass:
    def getUserId(self, login):
        return user_info["userid"]

    def getUserInfo(self, user_id):
        return user_info


mocked_resolver = MockedResolverClass()


def mocked_getResolverObject(resolver_spec):

    return mocked_resolver


class MockedLogging:
    log_data = []

    def info(self, *args, **kwargs):
        self.log("info", args, kwargs)

    def error(self, *args, **kwargs):
        self.log("error", args, kwargs)

    def log(self, mode, *args, **kwargs):
        for arg in args:
            self.log_data.append(arg)

        for key, val in list(kwargs.items()):
            self.log_data.append("[%s] %r:%r" % (mode, key, val))


mocked_logging = MockedLogging()

mocked_context = {}


class TestLoggingUserInResolver(unittest.TestCase):
    @patch("linotp.lib.user.getResolverObject", new=mocked_getResolverObject)
    @patch("linotp.lib.user.request_context", new=mocked_context)
    @patch("linotp.lib.user.log", new=mocked_logging)
    @patch("linotp.lib.user._get_user_lookup_cache")
    def test_login_user_data(self, mocked_get_user_lookup_cache):
        """test that no sensitive data got logged"""

        global mocked_context

        # ------------------------------------------------------------------ --

        # set up the required mocks for
        # - user_cache and
        # - request_context

        mocked_context["UserLookup"] = {}

        # build the dummy cache

        user_lookup_cache = UserLookupCache()

        user_lookup_cache.cache_return_value = (
            user_info["username"],
            user_info["userid"],
            user_info,
        )

        mocked_get_user_lookup_cache.return_value = user_lookup_cache

        # ------------------------------------------------------------------ --

        # first test - feed user data in cache

        lookup_user_in_resolver(
            login="hugo",
            user_id="123456",
            resolver_spec="linotp.passwdresolver.mypass",
            user_info=user_info,
        )

        # verify that no sensitiv data is in all the logged data

        for log_data in mocked_logging.log_data:
            assert user_info["password"] not in log_data

        # reset logging data

        mocked_logging.log_data = []

        # ------------------------------------------------------------------ --

        # 2. test - retrieve data from request cache

        lookup_user_in_resolver(
            login="hugo",
            user_id="123456",
            resolver_spec="linotp.passwdresolver.mypass",
            user_info=user_info,
        )

        # verify that no sensitiv data is in all the logged data

        for log_data in mocked_logging.log_data:
            assert user_info["password"] not in log_data

        # reset logging data

        mocked_logging.log_data = []

        # ------------------------------------------------------------------ --

        # 3. test - no cache is enabled and no data in the request local cache

        mocked_get_user_lookup_cache.return_value = None
        mocked_context["UserLookup"] = {}

        lookup_user_in_resolver(
            login="hugo",
            user_id="123456",
            resolver_spec="linotp.passwdresolver.mypass",
            user_info=user_info,
        )

        # verify that no sensitiv data is in all the logged data

        for log_data in mocked_logging.log_data:
            assert user_info["password"] not in log_data

        # reset logging data

        mocked_logging.log_data = []

        # ------------------------------------------------------------------ --

        # 4. test - no cache is enabled and no data in the request local cache
        #           so we end up calling the resolver

        mocked_get_user_lookup_cache.return_value = None
        mocked_context["UserLookup"] = {}

        lookup_user_in_resolver(
            login="hugo",
            user_id=None,
            resolver_spec="linotp.passwdresolver.mypass",
            user_info=None,
        )

        # verify that no sensitiv data is in all the logged data

        for log_data in mocked_logging.log_data:
            assert user_info["password"] not in log_data

        # reset logging data

        mocked_logging.log_data = []

        lookup_user_in_resolver(
            login=None,
            user_id="123456",
            resolver_spec="linotp.passwdresolver.mypass",
            user_info=None,
        )

        # verify that no sensitiv data is in all the logged data

        for log_data in mocked_logging.log_data:
            assert user_info["password"] not in log_data

        return
