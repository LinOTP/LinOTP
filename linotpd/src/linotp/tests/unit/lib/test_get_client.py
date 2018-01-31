#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

"""

import unittest


from mock import patch


from linotp.lib.util import _get_client_from_request

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

    @patch('linotp.lib.util.getFromConfig', mocked_getFromConfig)
    def test_get_client_from_request_by_x_forwarded_for(self):
        """
        test for request forwarding using HTTP_X_FORWARDED_FOR http header
        """

        # ------------------------------------------------------------------ --

        # 1. test - Forwarding is not enabled

        global LinConfig

        LinConfig = {}

        environ = {
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_X_FORWARDED_FOR': ''}

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client is not None)
        self.assertTrue(client == '127.0.0.1')

        # ------------------------------------------------------------------ --

        # 2. test - Forwarding is enabled
        # 2.a the proxy is not set
        # 2.b the proxy contains an single value
        # 2.c the proxy contains a list of ip values

        LinConfig = {
            'client.X_FORWARDED_FOR': 'true',
            'client.FORWARDED_PROXY': '', }

        environ = {
            'REMOTE_ADDR': '123.234.123.234',  # the last requester, the proxy
            'HTTP_X_FORWARDED_FOR': ('11.22.33.44 , '
                                     '12.22.33.44, '
                                     '123.234.123.234')  # the originator
            }

        # 2.a

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client == '123.234.123.234')

        # 2.b

        LinConfig = {
            'client.X_FORWARDED_FOR': 'true',
            'client.FORWARDED_PROXY': '123.234.123.234', }

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client == '11.22.33.44')

        # 2.c

        LinConfig = {
            'client.X_FORWARDED_FOR': 'true',
            'client.FORWARDED_PROXY': '121.121.121.121, 123.234.123.234', }

        request = Request(environ)
        client = _get_client_from_request(request)

        self.assertTrue(client == '11.22.33.44')

        # 3 wrong proxy format

        LinConfig = {
            'client.X_FORWARDED_FOR': 'true',
            'client.FORWARDED_PROXY': 'localhost, 123.234.123.234', }

        message = "invalid IPNetwork"
        request = Request(environ)
        with self.assertRaises(Exception) as exx:
            _get_client_from_request(request)

        self.assertTrue(message in exx.exception.message)

        return

    @patch('linotp.lib.util.getFromConfig', mocked_getFromConfig)
    def test_000_get_client_from_request_by_forwarded(self):
        """
        according to the spec the old expression is the same as the
        new one:

            X-Forwarded-For: 192.0.2.43, 2001:db8:cafe::17
       becomes:
           Forwarded: for=192.0.2.43, for="[2001:db8:cafe::17]

        """
        global LinConfig

        forward_test_strings = [
            ('for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown',
                '192.0.2.43'),
            ('for="_gazonk"', '_gazonk'),
            ('for="_gazonk:800"', '_gazonk'),
            ('For="[2001:db8:cafe::17]:4711"', '2001:db8:cafe::17'),
            ('for=192.0.2.60;proto=http;by=203.0.113.43', '192.0.2.60'),
            ('for=192.0.2.43, for=198.51.100.17', '192.0.2.43'),
            ]

        LinConfig = {
            'client.FORWARDED': 'true',
            'client.FORWARDED_PROXY': '121.121.121.121, 123.234.123.234', }

        environ = {
            'REMOTE_ADDR': '123.234.123.234',  # the last requester, the proxy
            }

        for forward_test_string in forward_test_strings:

            environ['Forwarded'] = forward_test_string[0]

            request = Request(environ)
            client = _get_client_from_request(request)

            self.assertTrue(client == forward_test_string[1], client)

# eof #
