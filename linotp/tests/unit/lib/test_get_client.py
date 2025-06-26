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
""" """

import socket
import unittest
from unittest.mock import patch

import netaddr
import pytest
from flask import current_app

from linotp.lib.type_utils import get_ip_address, get_ip_network
from linotp.lib.util import (
    _get_client_from_request,
    get_client,
    is_addr_in_network,
)

netw_dict = {
    "136.243.104.66/29": netaddr.IPNetwork("136.243.104.66/29"),
    "140.181.3.1/29": netaddr.IPNetwork("140.181.3.1/29"),
    "140.181.3.1/16": netaddr.IPNetwork("140.181.3.1/16"),
    "91.208.83.132": netaddr.IPNetwork("91.208.83.132/32"),
    "93.184.216.34/29": netaddr.IPNetwork("93.184.216.34/29"),
    "140.181.3.144": netaddr.IPNetwork("140.181.3.144/32"),
    "121.121.121.121": netaddr.IPNetwork("121.121.121.121/32"),
    "123.234.123.234": netaddr.IPNetwork("123.234.123.234"),
}

addr_dict = {
    "93.184.216.34": netaddr.IPAddress("93.184.216.34"),
    "136.243.104.66": netaddr.IPAddress("136.243.104.66"),
    "140.181.3.7": netaddr.IPAddress("140.181.3.7"),
    "140.181.3.121": netaddr.IPAddress("140.181.3.121"),
    "123.234.123.234": netaddr.IPAddress("123.234.123.234"),
}


def mock_IPNet(address):
    if address in [
        "my.other.test.domain/29",
        "www.my.test.domain",
        "my.local.test.domain",
    ]:
        msg = f"invalid IPNetwork {address!r}"
        raise netaddr.core.AddrFormatError(msg)

    return netw_dict.get(address)


def mock_IPAddr(address):
    if address in ["www.my.test.domain"]:
        msg = f"invalid IPNetwork {address!r}"
        raise netaddr.core.AddrFormatError(msg)

    return addr_dict.get(address)


# client.FORWARDED_PROXY
# client.X_FORWARDED_FOR
LinConfig = {}


def mocked_getFromConfig(key, default):
    return LinConfig.get(key, default)


class Request:
    def __init__(self, environ, values=None):
        self.environ = environ
        self.values = values or {}
        self.is_json = False


@pytest.mark.usefixtures("app")
class TestGetClientCase(unittest.TestCase):
    """
    unit test for methods to access the client information
    """

    @patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
    def test_get_client_from_request_by_x_forwarded_for_with_TRUSTED_PROXIES_setting(
        self,
    ):
        """
        When the TRUSTED_PROXIES setting item is set, the x_forwarded_for setting (which is
        currently set through the UI) does not take effect. i.e. the get_client would not affect
        remote_addr.
        """

        current_app.config["TRUSTED_PROXIES"] = ["mytrustedproxy.proxy"]

        global LinConfig
        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "123.234.123.234",
        }

        environ = {
            "REMOTE_ADDR": "123.234.123.234",
            "HTTP_X_FORWARDED_FOR": "11.22.33.44",
        }

        request = Request(environ)
        client = _get_client_from_request(request)

        # remote address has not changed
        assert client == "123.234.123.234"

    @patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
    def test_get_client_from_request_by_x_forwarded_for(self):
        """
        test for request forwarding using HTTP_X_FORWARDED_FOR http header
        """

        # ------------------------------------------------------------------ --

        # 1. test - Forwarding is not enabled

        global LinConfig

        LinConfig = {}

        environ = {"REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_FOR": ""}

        request = Request(environ)
        client = _get_client_from_request(request)

        assert client is not None
        assert client == "127.0.0.1"

        # ------------------------------------------------------------------ --

        # 2. test - Forwarding is enabled
        # 2.a the proxy is not set
        # 2.b the proxy contains an single value
        # 2.c the proxy contains a list of ip values

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "",
        }

        environ = {
            "REMOTE_ADDR": "123.234.123.234",  # the last requester, the proxy
            "HTTP_X_FORWARDED_FOR": (
                "11.22.33.44 , 12.22.33.44, 123.234.123.234"
            ),  # the originator
        }

        # 2.a

        request = Request(environ)
        client = _get_client_from_request(request)

        assert client == "123.234.123.234"

        # 2.b

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "123.234.123.234",
        }

        request = Request(environ)
        client = _get_client_from_request(request)

        assert client == "11.22.33.44"

        # 2.c

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "121.121.121.121, 123.234.123.234",
        }

        request = Request(environ)
        client = _get_client_from_request(request)

        assert client == "11.22.33.44"

        # 3 wrong proxy format

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "www.my.test.domain, 123.234.123.234",
        }

        request = Request(environ)

        # with self.assertRaises(Exception) as exx:
        client = _get_client_from_request(request)
        assert client == "11.22.33.44"

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "11.22.33.0/32, 123.234.123.234",
        }

        request = Request(environ)

        # with self.assertRaises(Exception) as exx:
        client = _get_client_from_request(request)
        assert client == "11.22.33.44"

        # 4 missing/empty X_FORWARDED_FOR header of a FORWARDED_PROXY
        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "123.234.123.234",
        }
        environ = {"REMOTE_ADDR": "123.234.123.234"}
        request = Request(environ)

        client = _get_client_from_request(request)
        assert client == "123.234.123.234"

    @patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
    @patch("linotp.lib.type_utils.netaddr.IPNetwork", mock_IPNet)
    @patch("linotp.lib.type_utils.netaddr.IPAddress", mock_IPAddr)
    def test_get_client_from_request_by_forwarded(self):
        """
         according to the spec the old expression is the same as the
         new one:

             X-Forwarded-For: 192.0.2.43, 2001:db8:cafe::17
        becomes:
            Forwarded: for=192.0.2.43, for="[2001:db8:cafe::17]

        """
        global LinConfig

        forward_test_strings = [
            (
                'for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown',
                "192.0.2.43",
            ),
            ('for="_gazonk"', "_gazonk"),
            ('for="_gazonk:800"', "_gazonk"),
            ('For="[2001:db8:cafe::17]:4711"', "2001:db8:cafe::17"),
            ("for=192.0.2.60;proto=http;by=203.0.113.43", "192.0.2.60"),
            ("for=192.0.2.43, for=198.51.100.17", "192.0.2.43"),
        ]

        LinConfig = {
            "client.FORWARDED": "true",
            "client.FORWARDED_PROXY": "121.121.121.121, 123.234.123.234",
        }

        environ = {
            "REMOTE_ADDR": "123.234.123.234",  # the last requester, the proxy
        }

        for forward_test_string in forward_test_strings:
            environ["Forwarded"] = forward_test_string[0]

            request = Request(environ)
            client = _get_client_from_request(request)

            assert client == forward_test_string[1], client

        # missing/empty FORWARDED header of a FORWARDED_PROXY
        LinConfig = {
            "client.FORWARDED": "true",
            "client.FORWARDED_PROXY": "123.234.123.234",
        }
        environ = {"REMOTE_ADDR": "123.234.123.234"}
        request = Request(environ)

        client = _get_client_from_request(request)
        assert client == "123.234.123.234", client

    @patch("linotp.lib.type_utils.netaddr.IPNetwork", mock_IPNet)
    @patch("linotp.lib.type_utils.netaddr.IPAddress", mock_IPAddr)
    def test_ipaddr_value(self):
        """unit test for get_ip_address"""

        with patch("linotp.lib.type_utils.socket.gethostbyname") as mHostName:
            mHostName.return_value = "91.208.83.132"
            ip_address = get_ip_address("www.my.test.domain")

            ip_tuple = ip_address.words
            assert (91, 208, 83, 132) == ip_tuple

        ip_addr = get_ip_address("93.184.216.34")
        ip_tuple = ip_addr.words
        assert (93, 184, 216, 34) == ip_tuple

        ip_addr = get_ip_address("93.184.216.34/32")
        assert ip_addr is None

        ip_addr = get_ip_address("does_not_exist.domain")
        assert ip_addr is None

        ip_addr = get_ip_address("  ")
        assert ip_addr is None

        return

    @patch("linotp.lib.type_utils.netaddr.IPNetwork", mock_IPNet)
    @patch("linotp.lib.type_utils.netaddr.IPAddress", mock_IPAddr)
    def test_network_value(self):
        """unit test for get_ip_network"""

        ip_network = get_ip_network("93.184.216.34/29")
        assert len(list(ip_network)) == 8
        ip_tuple = ip_network.network.words
        assert (93, 184, 216, 32) == ip_tuple

        with patch("linotp.lib.type_utils.socket.gethostbyname") as mHostName:
            mHostName.return_value = "140.181.3.144"

            ip_network = get_ip_network("my.local.test.domain")
            ip_tuple = ip_network.network.words
            ip_range = (ip_tuple[0], ip_tuple[1], ip_tuple[2])
            assert (140, 181, 3) == ip_range

        with patch("linotp.lib.type_utils.socket.gethostbyname") as mHostName:
            mHostName.return_value = "136.243.104.66"

            ip_network = get_ip_network("my.other.test.domain/29")
            assert len(list(ip_network)) == 8
            ip_tuple = ip_network.network.words
            ip_range = (ip_tuple[0], ip_tuple[1], ip_tuple[2])
            assert (136, 243, 104) == ip_range

        with patch("linotp.lib.type_utils.socket.gethostbyname") as mHostName:
            mHostName.side_effect = socket.gaierror(
                "[Errno 8] nodename nor servname provided, or not known"
            )

            ip_network = get_ip_network("does_not_exist.domain")
            assert ip_network is None

        ip_network = get_ip_network("  ")
        assert ip_network is None

        ip_network = get_ip_network(None)
        assert ip_network is None

    @patch("linotp.lib.type_utils.netaddr.IPNetwork", mock_IPNet)
    @patch("linotp.lib.type_utils.netaddr.IPAddress", mock_IPAddr)
    def test_addr_in_network(self):
        """unit test for _is_addr_in_network"""

        with patch("linotp.lib.type_utils.socket.gethostbyname") as mHostName:
            mHostName.return_value = "136.243.104.66"

            in_network = is_addr_in_network("136.243.104.66", "my.other.test.domain/29")
            assert in_network is True

        in_network = is_addr_in_network("140.181.3.7", "140.181.3.1/29")
        assert in_network is True

        in_network = is_addr_in_network(" 140.181.3.121", " 140.181.3.1/16 ")
        assert in_network is True

        in_network = is_addr_in_network("140.181.3.121", " ")
        assert in_network is False

        with patch("linotp.lib.type_utils.socket.gethostbyname") as mHostName:
            mHostName.side_effect = socket.gaierror(
                "[Errno 8] nodename nor servname provided, or not known"
            )

            in_network = is_addr_in_network("140.181.3.121", "www.my.test.domain ")
            assert in_network is False

        return


# Test (deprecated) `client=ADDR` POST parameter feature, including
# whether it can be enabled/disabled using the
# `GET_CLIENT_ADDRESS_FROM_POST_DATA` config item.


@pytest.mark.parametrize(
    "use_post,overwriters,issue_warning,result",
    [
        (False, "", False, "11.12.13.14"),
        (False, "11.12.13.14", False, "11.12.13.14"),
        (True, "", False, "11.12.13.14"),
        (True, "11.12.13.14", True, "15.16.17.18"),
        (True, "11.12.13.13,11.12.13.14,11.12.13.15", True, "15.16.17.18"),
        (True, "11.12.13.13, 11.12.13.14 ,11.12.13.15", True, "15.16.17.18"),
        (True, "11.12.13.13,11.12.13.15", False, "11.12.13.14"),
    ],
)
@patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
def test_get_client_from_post_data(
    caplog, app, use_post, overwriters, issue_warning, result
):
    MESSAGE = "DEPRECATION WARNING: Passing the client IP address in POST "
    app.config["GET_CLIENT_ADDRESS_FROM_POST_DATA"] = use_post
    LinConfig["mayOverwriteClient"] = overwriters
    request = Request(
        environ={"REMOTE_ADDR": "11.12.13.14"},
        values={"client": "15.16.17.18"},
    )
    caplog.clear()
    addr = get_client(request)
    assert addr == result
    if issue_warning:
        assert any(msg.startswith(MESSAGE) for msg in caplog.messages)


@patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
def test_get_client_from_post_data_no_client_parameter(app):
    app.config["GET_CLIENT_ADDRESS_FROM_POST_DATA"] = True
    LinConfig["mayOverwriteClient"] = "11.12.13.14"
    request = Request(
        environ={"REMOTE_ADDR": "11.12.13.14"},
        values={},
    )
    assert get_client(request) == "11.12.13.14"


@patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
def test_get_client_from_post_data_malformed_client(app):
    app.config["GET_CLIENT_ADDRESS_FROM_POST_DATA"] = True
    LinConfig["mayOverwriteClient"] = "11.12.13.14"
    request = Request(
        environ={"REMOTE_ADDR": "11.12.13.14"},
        values={"client": "foobar"},
    )
    with pytest.raises(ValueError) as ex:
        get_client(request)
    assert str(ex.value) == "client address is not a dotted quad: 'foobar'"


# eof #
