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

from datetime import datetime, timedelta
from unittest import TestCase

import pytest
from mock import patch

from linotp.lib.remote_service import (
    AllServicesUnavailable,
    RemoteServiceList,
    State,
)


class CustomException(Exception):
    pass


def generate_variadic_func(exception=Exception, default=False):
    def func(*args, **kwargs):
        func.call_count += 1
        if func.fail:
            raise exception()

        return args, kwargs

    func.fail = default
    func.call_count = 0

    return func


def generate_failing_func(exception=Exception):
    return generate_variadic_func(exception=exception, default=True)


def generate_passthru_func():
    return generate_variadic_func(default=False)


class TestRemoteServiceList(TestCase):
    def test_emtpy_remote_service_list(self):
        """
        A list without services should throw an AllServicesUnavailable exception
        """
        services = RemoteServiceList()
        with pytest.raises(AllServicesUnavailable):
            services.call_first_available()

    def test_failing_service_list_should_throw(self):
        """
        A list of failing services should throw an AllServicesUnavailable exception
        """
        services = RemoteServiceList()
        services.append(generate_failing_func())
        services.append(generate_failing_func())

        with pytest.raises(AllServicesUnavailable):
            services.call_first_available()

    def test_passes_arguments(self):
        """
        A service should get arguments passed on
        """
        services = RemoteServiceList()
        services.append(lambda arg: arg)
        assert services.call_first_available(42) == 42

    def test_passes_kwargs(self):
        """
        A function should get keyword-arguments passed on
        """
        services = RemoteServiceList()
        services.append(generate_passthru_func())

        # the arguments we pass into the service should be returned for
        # investigation
        args, kwargs = services.call_first_available(
            1, 2, 3, one=1, two=2, three=3
        )

        assert args == (1, 2, 3)
        assert kwargs == dict(one=1, two=2, three=3)

    def test_service_failover(self):
        """
        Services that fail should cause a failover to another service on first failure
        """
        services = RemoteServiceList()
        func = generate_failing_func()
        services.append(func)
        services.append(lambda: 42)

        assert services.call_first_available() == 42
        assert func.call_count == 1

    def test_custom_exception_handling(self):
        """
        A custom exception should be caught successfully
        """
        services = RemoteServiceList(expected_exception=CustomException)
        func = generate_failing_func(exception=CustomException)
        services.append(func)
        services.append(lambda: 23)

        assert services.call_first_available() == 23
        assert func.call_count == 1

    def test_service_is_marked_as_unavailable(self):
        """
        Verify that a function that is failing `failure_threshold` times is
        marked as broken and skipped
        """

        # create a list of service where the first function yields an exception
        services = RemoteServiceList(expected_exception=CustomException)
        func = generate_failing_func(exception=CustomException)
        services.append(func)
        services.append(lambda: 42)

        # initially all services should be marked as functional
        assert services[0].state == State.FUNCTIONAL
        assert services[1].state == State.FUNCTIONAL

        # after calling for `failure_threshold` times the failing service
        # should be marked as UNAVAILABLE
        for _ in range(0, services.failure_threshold):
            assert services.call_first_available() == 42

        assert func.call_count > 0
        assert func.call_count == services.failure_threshold
        assert services[0].state == State.UNAVAILABLE

        # the second function must still be FUNCTIONAL
        assert services[1].state == State.FUNCTIONAL

        # and return the expected value
        assert services.call_first_available() == 42

    @patch("linotp.lib.remote_service.now")
    def test_recovery(self, dt_now):
        """
        Ensure that a failing function recovers after the configured timeout.
        Before the timeout expires other good functions should be used.
        """

        # build a service list with a variadic function & a lambda that tells
        # us that we are in failover mode
        services = RemoteServiceList(expected_exception=CustomException)
        func = generate_variadic_func(exception=CustomException)
        services.append(func)
        services.append(lambda: "failover")

        # record the current time for our mocking
        start_time = datetime.now()

        # initially return the current time
        dt_now.return_value = start_time

        # calling the function (before it is marked as failing) returns the
        # input parameters (as expected)
        assert services.call_first_available(1) == ((1,), {})

        # mark the first function in the list as failing & move into the future
        func.fail = True
        dt_now.return_value += timedelta(seconds=1)

        # call n times until the function is marked as failed
        for _ in range(0, services.failure_threshold):
            assert services.call_first_available() == "failover"

        assert services[0].state == State.UNAVAILABLE

        # Every second until recovery call the first available service
        # The return value should always be 'failover'
        while dt_now.return_value <= start_time + timedelta(
            seconds=services.recovery_timeout
        ):
            assert services.call_first_available() == "failover"
            dt_now.return_value += timedelta(seconds=1)

        # the state of the primary function should still be UNAVAILABLE
        assert services[0].state == State.UNAVAILABLE
        assert services[1].state == State.FUNCTIONAL

        # tell function to return again
        func.fail = False

        # after the recovery timeout the first service should start returing
        # again
        dt_now.return_value += timedelta(seconds=1)
        assert services.call_first_available(1) == ((1,), {})
        assert services[0].state == State.FUNCTIONAL
