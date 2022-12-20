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

from datetime import datetime, timedelta


def now():
    """
    Return the current time.

    This function is required for datetime mocking during testing.
    """
    return datetime.now()


class State(object):
    """
    State of a Service
    """

    FUNCTIONAL = 1
    UNAVAILABLE = 2


class ServiceUnavailable(Exception):
    """
    Thrown when a service is unavailable.

    This exception is used for failover to other services and not passed to
    users.
    """

    pass


class AllServicesUnavailable(Exception):
    """
    Thrown when all services are unavailable.

    This exception will be passed on to callers of
    `RemoteService.call_first_available` when there are no functional services
    left.
    """

    pass


class RemoteService(object):
    """
    A service that keeps track of it failures and marks itself as unavilable
    after an exceeding amount of configured (base) exceptions.
    """

    def __init__(
        self,
        func,
        failure_threshold=5,
        recovery_timeout=30,
        expected_exception=Exception,
    ):

        self.func = func
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.last_unavailable = None
        self.state = State.FUNCTIONAL

    def on_recovery(self):
        self.failure_count = 0
        self.state = State.FUNCTIONAL

    def on_failure(self):
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.last_unavailable = now()
            self.state = State.UNAVAILABLE

    def __call__(self, *args, **kwargs):
        """
        Calls the wrapped function

        :raises ServiceUnavailable: If function call did not succeed or
            recovery time for the function has not passed.
        """

        if self.state == State.UNAVAILABLE:

            if now() > self.last_unavailable + timedelta(
                seconds=self.recovery_timeout
            ):

                # recovery time is over. try once(!) if function
                # is available again

                try:
                    result = self.func(*args, **kwargs)
                    self.on_recovery()
                    return result
                except self.expected_exception as e:
                    self.on_failure()
                    raise ServiceUnavailable(repr(e))

            else:

                # recovery time is not over.
                # simply raise exception

                raise ServiceUnavailable()

        # service state is FUNCTIONAL

        try:
            result = self.func(*args, **kwargs)
            return result
        except self.expected_exception as e:
            self.on_failure()
            raise ServiceUnavailable(repr(e))


class RemoteServiceList(list):
    """
    A list of services that will transparently failover to the next service if one failes.
    """

    def __init__(
        self,
        failure_threshold=5,
        recovery_timeout=30,
        expected_exception=Exception,
    ):

        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

    def append(self, func, **kwargs):

        service_kwargs = {
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "expected_exception": self.expected_exception,
        }

        service_kwargs.update(kwargs)

        service = RemoteService(func, **service_kwargs)
        list.append(self, service)

    def call_first_available(self, *args, **kwargs):
        """
        calls the first available service with the supplied
        arguments.

        :raises AllServicesUnavailable: If no service is available
            at the moment
        """

        for service in self:

            try:
                result = service(*args, **kwargs)
                return result
            except ServiceUnavailable:
                continue

        else:

            # no service in list succeeded
            raise AllServicesUnavailable()
