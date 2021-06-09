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

import os
import logging
import requests

from mock import patch

from requests.exceptions import ConnectionError

from linotp.tests import TestController
from linotp.provider.pushprovider.default_push_provider import (
    DefaultPushProvider,
)
import pytest


"""
    functional test for the DefaultPushProvider:

    - check the DefaultPushProvider functions

"""

VALID_REQUEST = "You received an authentication request."

log = logging.getLogger(__name__)


def generate_mocked_http_response(status=200, text=VALID_REQUEST):
    def mocked_http_request(*argparams, **kwparams):
        class Response:
            pass

        r = Response()

        r.status = status
        r.text = text

        if r.status == 200:
            r.ok = True
            r.content = r.text
            return r

        r.ok = False
        r.reason = r.text

        return r

    return mocked_http_request


class TestPushProviderController(TestController):
    """
    test the push provider
    """

    def setUp(self):
        return

    def tearDown(self):
        self.delete_all_resolvers()
        super(TestPushProviderController, self).tearDown()

    def test_timeout_negative(self):
        """
        Verify that a negative timeout value throws an ValueError
        """

        push_prov = DefaultPushProvider()
        with pytest.raises(ValueError):
            push_prov.loadConfig(dict(timeout="-1", push_url="https://x"))

    def test_timeout_invalid_tuple_size(self):
        """
        Verify that tuples with a size != 2 cause an ValueError
        """

        push_prov = DefaultPushProvider()
        with pytest.raises(ValueError):
            push_prov.loadConfig(dict(timeout="1,", push_url="https://x"))

        with pytest.raises(ValueError):
            push_prov.loadConfig(dict(timeout="1,2,3", push_url="https://x"))

        with pytest.raises(ValueError):
            push_prov.loadConfig(dict(timeout="1,2,3,", push_url="https://x"))

        with pytest.raises(ValueError):
            push_prov.loadConfig(dict(timeout="1,2,3,4", push_url="https://x"))

    def test_timeout_doesnt_accept_strings(self):
        """
        Verify that the timeout parameter only accepts numbers (int, float) and
        not strings (str, unicode, …)
        """

        push_prov = DefaultPushProvider()

        for s in [
            "invalid timeout",
            "invalid,timeout",
            "1,timeout",
            "invalid,1",
        ]:
            v = str(s)
            with pytest.raises(ValueError):
                push_prov.loadConfig(dict(timeout=v, push_url="https://x"))

        with pytest.raises(ValueError):
            push_prov.loadConfig(
                dict(timeout="invalid,timeout", push_url="https://x")
            )

        with pytest.raises(ValueError):
            push_prov.loadConfig(
                dict(timeout="1,timeout", push_url="https://x")
            )

        with pytest.raises(ValueError):
            push_prov.loadConfig(
                dict(timeout="invalid,1", push_url="https://x")
            )

    def test_read_config(self):
        """
        test push provider configuration handling
        """

        configDict = {}
        push_prov = DefaultPushProvider()

        #
        # first test the valid configuration
        #

        configDict["Timeout"] = "30"
        configDict["access_certificate"] = os.path.join(
            self.fixture_path, "cert.pem"
        )

        configDict["push_url"] = [
            "https://Notification1.keyidentity.com/send",
            "https://Notification2.keyidentity.com/send",
        ]

        push_prov.loadConfig(configDict)

        #
        # verify that we support loading of timeout tuples
        #

        configDict["Timeout"] = "3,10"
        push_prov.loadConfig(configDict)
        assert push_prov.timeout == (3.0, 10.0)

        #
        # verify server url check
        #

        with pytest.raises(requests.exceptions.InvalidSchema):
            configDict["push_url"] = "hXXXs://proxy.keyidentity.com:8800/send"
            push_prov.loadConfig(configDict)

        #
        # verify that multiple urls are also being checked
        #

        with pytest.raises(requests.exceptions.InvalidSchema):
            configDict["push_url"] = [
                "https://proxy.keyidentity.com:8800/send",
                "hXXXs://proxy.keyidentity.com:8800/send",
            ]
            push_prov.loadConfig(configDict)

        #
        # restore configuration for push_url
        #

        configDict["push_url"] = [
            "https://Notification1.keyidentity.com/send",
            "https://Notification2.keyidentity.com/send",
        ]

        #
        # extended option: proxy
        #

        configDict["proxy"] = "https://proxy.keyidentity.com:8800/"
        push_prov.loadConfig(configDict)

        #
        # extended option: proxy with wrong url scheme
        #

        with pytest.raises(requests.exceptions.InvalidSchema):
            configDict["proxy"] = "hXXXs://proxy.keyidentity.com:8800/"
            push_prov.loadConfig(configDict)

        # restore valid proxy url
        configDict["proxy"] = "https://proxy.keyidentity.com:8800/"

        #
        # valid extended timeout format
        #

        configDict["timeout"] = "3,10"
        push_prov.loadConfig(configDict)

        del configDict["timeout"]

        #
        # invalid timeout format: "invalid literal for float()"
        #

        with pytest.raises(ValueError):
            configDict["Timeout"] = "30s"
            push_prov.loadConfig(configDict)

        # timeout has a default and is not required
        del configDict["Timeout"]

        #
        # non existing certificate file - should raise exception
        # 'required authenticating client cert could not be found'
        #

        with pytest.raises(IOError):
            cert_file_name = os.path.join(self.fixture_path, "non_exist.pem")
            configDict["access_certificate"] = cert_file_name
            push_prov.loadConfig(configDict)

        # restore access certificate parameter
        cert_file_name = os.path.join(self.fixture_path, "cert.pem")
        configDict["access_certificate"] = cert_file_name

        # check if missing push_url is as well detected
        with pytest.raises(KeyError):
            del configDict["push_url"]
            push_prov.loadConfig(configDict)

        # restore required push_url
        configDict["push_url"] = "https://Notification.keyidentity.com/send"

        #
        # check if server cert is provided, the existance of directory or
        # file is made
        #

        server_cert_file_name = os.path.join(self.fixture_path, "cert.pem")
        configDict["server_certificate"] = server_cert_file_name
        push_prov.loadConfig(configDict)

        with pytest.raises(IOError):
            server_cert_file_name = "/abc/ssl/certs"
            configDict["server_certificate"] = server_cert_file_name
            push_prov.loadConfig(configDict)

        return

    @patch.object(requests, "post", generate_mocked_http_response())
    def test_request(self):
        """
        do some mocking of a requests request
        """

        configDict = {}
        configDict["Timeout"] = "30"
        configDict["access_certificate"] = os.path.join(
            self.fixture_path, "cert.pem"
        )
        configDict["push_url"] = "https://notification.keyidentity.com/send"

        push_prov = DefaultPushProvider()
        push_prov.loadConfig(configDict)

        push_prov = DefaultPushProvider()
        push_prov.loadConfig(configDict)
        gda = (
            "apn.98c78e19e9842a1cfdeb887bf42142b615865b1ec513"
            "c31ea1a4f3222660435f"
        )
        message = "Authentication request for user bla"

        # run the fake request
        status, response = push_prov.push_notification(
            challenge=message, gda=gda, transactionId="012345678901234"
        )

        assert status == True
        assert response == VALID_REQUEST

        return


def cond_failing_http_response(*args, **kwargs):

    url = args[0]

    assert type(url) is str

    if "success" in url:
        return generate_mocked_http_response()(*args, **kwargs)

    raise requests.ConnectionError("this request should fail")


class TestPushProviderFailover(TestController):
    def _test_servers(self, servers):
        configDict = {}
        configDict["Timeout"] = "30"
        configDict["access_certificate"] = os.path.join(
            self.fixture_path, "cert.pem"
        )
        configDict["push_url"] = servers

        push_prov = DefaultPushProvider()
        push_prov.loadConfig(configDict)

        push_prov = DefaultPushProvider()
        push_prov.loadConfig(configDict)
        gda = (
            "apn.98c78e19e9842a1cfdeb887bf42142b615865b1ec513"
            "c31ea1a4f3222660435f"
        )
        message = "Authentication request for user bla"

        # run the fake request
        status, response = push_prov.push_notification(
            challenge=message, gda=gda, transactionId="012345678901234"
        )

        assert status == True
        assert response == VALID_REQUEST

    @patch.object(requests, "post", cond_failing_http_response)
    def test_single_server(self):
        """
        Verify that a single server suceeds
        """

        self._test_servers(["https://success.server/push"])

    @patch.object(requests, "post", cond_failing_http_response)
    def test_single_failing_server(self):
        """
        verify that a single faiiling server should return failure
        """
        with pytest.raises(ConnectionError):
            self._test_servers(["https://failing.server/"])

    @patch.object(requests, "post", cond_failing_http_response)
    def test_multiple_servers(self):
        """
        Verify that multiple servers of which one fails succeeds
        """

        self._test_servers(
            [
                "https://failing1.server/push",
                "https://failing2.server/push",
                "https://success2.server/push",
            ]
        )
