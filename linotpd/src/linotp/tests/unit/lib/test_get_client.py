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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""

"""

import unittest

from mock import patch

from linotp.lib.type_utils import get_ip_address, get_ip_network
from linotp.lib.util import _get_client_from_request, _is_addr_in_network

# client.FORWARDED_PROXY
# client.X_FORWARDED_FOR
LinConfig = {}


def mocked_getFromConfig(key, default):
    return LinConfig.get(key, default)


class Request(object):
    def __init__(self, environ):
        self.environ = environ


class TestGetClientCase(unittest.TestCase):
    """
    unit test for methods to access the client information
    """

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

        self.assertTrue(client is not None)
        self.assertTrue(client == "127.0.0.1")

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
                "11.22.33.44 , " "12.22.33.44, " "123.234.123.234"
            ),  # the originator
        }

        # 2.a

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client == "123.234.123.234")

        # 2.b

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "123.234.123.234",
        }

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client == "11.22.33.44")

        # 2.c

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "121.121.121.121, 123.234.123.234",
        }

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client == "11.22.33.44")

        # 3 wrong proxy format

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "www.example.com.xx, 123.234.123.234",
        }

        request = Request(environ)

        # with self.assertRaises(Exception) as exx:
        client = _get_client_from_request(request)
        self.assertTrue(client == "11.22.33.44")

        LinConfig = {
            "client.X_FORWARDED_FOR": "true",
            "client.FORWARDED_PROXY": "11.22.33.0/32, 123.234.123.234",
        }

        request = Request(environ)

        # with self.assertRaises(Exception) as exx:
        client = _get_client_from_request(request)
        self.assertTrue(client == "11.22.33.44")

        return

    @patch("linotp.lib.util.getFromConfig", mocked_getFromConfig)
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
            ('for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown', "192.0.2.43"),
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

            self.assertTrue(client == forward_test_string[1], client)

    def test_ipaddr_value(self):
        """unit test for get_ip_address"""
        ip_address = get_ip_address("www.example.com")
        ip_tuple = ip_address.words
        assert (93, 184, 216, 34) == ip_tuple

        ip_addr = get_ip_address("93.184.216.34")
        ip_tuple = ip_addr.words
        assert (93, 184, 216, 34) == ip_tuple

        ip_addr = get_ip_address("93.184.216.34/32")
        assert ip_addr is None

        ip_addr = get_ip_address("example.com.xxx")
        assert ip_addr is None

        ip_addr = get_ip_address("  ")
        assert ip_addr is None

        return

    def test_network_value(self):
        """unit test for get_ip_network"""

        ip_network = get_ip_network("93.184.216.34/29")
        assert len(list(ip_network)) == 8
        ip_tuple = ip_network.network.words
        assert (93, 184, 216, 32) == ip_tuple

        ip_network = get_ip_network("gsi.de")
        ip_tuple = ip_network.network.words
        ip_range = (ip_tuple[0], ip_tuple[1], ip_tuple[2])
        assert (140, 181, 3) == ip_range

        ip_network = get_ip_network("keyidentity.com/29")
        assert len(list(ip_network)) == 8
        ip_tuple = ip_network.network.words
        ip_range = (ip_tuple[0], ip_tuple[1], ip_tuple[2])
        assert (136, 243, 104) == ip_range

        ip_network = get_ip_network("example.xxx")
        assert ip_network is None

        ip_network = get_ip_network("  ")
        assert ip_network is None

        ip_network = get_ip_network(None)
        assert ip_network is None

        return

    def test_addr_in_network(self):
        """unit test for _is_addr_in_network"""

        in_network = _is_addr_in_network("136.243.104.66", "keyidentity.com/29")
        assert in_network is True

        in_network = _is_addr_in_network("140.181.3.7", "140.181.3.1/29")
        assert in_network is True

        in_network = _is_addr_in_network(" 140.181.3.121", " 140.181.3.1/16 ")
        assert in_network is True

        in_network = _is_addr_in_network("140.181.3.121", " ")
        assert in_network is False

        in_network = _is_addr_in_network("140.181.3.121", "example.net.xxx ")
        assert in_network is False

        return


# eof #
