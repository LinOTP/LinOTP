# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


"""
Test the 'httperror' parameter that is interpreted in
linotp.lib.reply.sendError()

This parameter allows a client to specify that he/she wants a custom HTTP
status code instead of a standard JSON 200 OK (with error description) response
in case of an error.
"""


from distutils.version import LooseVersion
import pkg_resources
import logging

from linotp.tests import TestController, url

log = logging.getLogger(__name__)


def _webob_version():
    return LooseVersion(
        pkg_resources.get_distribution('webob').version
        )

def _get_status_code(response):
    """
    Once upon a time WebOb deprecated status_code and encouraged the use of
    status_int, then in version 1.2 the deprecation was reverted and now it
    is recommended to use status_code instead of status_int. (The
    deprecation actually raises an exception and causes all tests to fail).

    :param response: A WebOb response object
    """
    current_webob = _webob_version()
    if current_webob >= LooseVersion('1.2'):
        return response.status_code
    else:
        return response.status_int


class TestHTTPError(TestController):

    def setUp(self):
        TestController.setUp(self)
        # Delete 'errors' entry from Config, in case it is set
        self._del_errors_from_config()

    def test_no_httperror(self):
        """
        Default case: No httperror sent. Response is JSON 200 OK
        """
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            }
        response = self.make_admin_request('init', params)
        content = self.get_json_body(response)

        self.assertEqual(_get_status_code(response), 200)
        self.assertEqual(response.content_type, 'application/json')
        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertFalse(content['result']['status'])
        self.assertIn('error', content['result'])
        self.assertIn('message', content['result']['error'])
        self.assertIn('code', content['result']['error'])
        # ERR1112: getUserResolverId failed
        self.assertEqual(content['result']['error']['code'], 1112)

    def test_httperror(self):
        """
        Send 'httperror' in request and verify same HTTP status is returned.
        """
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': 444,
            }
        response = self._make_admin_request_custom_status('init', params, 444)

        self.assertEqual(_get_status_code(response), 444)
        self.assertEqual(response.content_type, 'text/html')
        self.assertIn("ERR1112: getUserResolverId failed", response)

    def test_empty_httperror(self):
        """
        Send empty 'httperror' in request and verify status 500 is returned.
        """
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': '',
            }
        response = self._make_admin_request_custom_status('init', params, 500)

        self.assertEqual(_get_status_code(response), 500)
        self.assertEqual(response.content_type, 'text/html')
        self.assertIn("ERR1112: getUserResolverId failed", response)

    def test_httperror_errid_in_config(self):
        """
        Verify httperror returned if errId in Config.errors

        If 'errors' in LinOTP Config is set, and the ID of the error that is
        raised (1112 in this case) is contained in that list, then a HTTP
        status 'httperror' is returned.
        """
        self._set_errors_in_config('233,567,1112')

        # Test request httperror 444
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': 444,
            }
        response = self._make_admin_request_custom_status('init', params, 444)

        self.assertEqual(_get_status_code(response), 444)
        self.assertEqual(response.content_type, 'text/html')
        self.assertIn("ERR1112: getUserResolverId failed", response)

        # Test request httperror empty
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': '',
            }
        response = self._make_admin_request_custom_status('init', params, 500)

        self.assertEqual(_get_status_code(response), 500)
        self.assertEqual(response.content_type, 'text/html')
        self.assertIn("ERR1112: getUserResolverId failed", response)


    def test_httperror_errid_not_in_config(self):
        """
        Verify httperror ignored if errId not in Config.errors

        If 'errors' in LinOTP Config is set, and the ID of the error that is
        raised (1112 in this case) is NOT in that list, then a regular JSON
        response is returned.
        """
        self._set_errors_in_config('233,567')

        # Test request httperror 444
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': 444,
            }
        response = self.make_admin_request('init', params)
        content = self.get_json_body(response)

        self.assertEqual(_get_status_code(response), 200)
        self.assertEqual(response.content_type, 'application/json')
        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertFalse(content['result']['status'])
        self.assertIn('error', content['result'])
        self.assertIn('message', content['result']['error'])
        self.assertIn('code', content['result']['error'])
        # ERR1112: getUserResolverId failed
        self.assertEqual(content['result']['error']['code'], 1112)

        # Test request httperror empty
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': '',
            }
        response = self.make_admin_request('init', params)
        content = self.get_json_body(response)

        self.assertEqual(_get_status_code(response), 200)
        self.assertEqual(response.content_type, 'application/json')
        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertFalse(content['result']['status'])
        self.assertIn('error', content['result'])
        self.assertIn('message', content['result']['error'])
        self.assertIn('code', content['result']['error'])
        # ERR1112: getUserResolverId failed
        self.assertEqual(content['result']['error']['code'], 1112)


    def test_no_httperror_with_config(self):
        """
        Presence of 'errors' in Config makes no difference without httperror

        Even if 'errors' in LinOTP Config is set, it makes no difference as
        long as no 'httperror' parameter is not sent in the request. A JSON 200
        OK response is returned.
        """
        self._set_errors_in_config('233,567')

        # Test request (no httperror)
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            }
        response = self.make_admin_request('init', params)
        content = self.get_json_body(response)

        self.assertEqual(_get_status_code(response), 200)
        self.assertEqual(response.content_type, 'application/json')
        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertFalse(content['result']['status'])
        self.assertIn('error', content['result'])
        self.assertIn('message', content['result']['error'])
        self.assertIn('code', content['result']['error'])
        # ERR1112: getUserResolverId failed
        self.assertEqual(content['result']['error']['code'], 1112)


    def test_httperror_and_config_set_but_empty(self):
        """
        If 'errors' in Config is empty 'httperror' triggers status httperror

        If 'errors' in LinOTP Config is set but empty all errIds cause HTTP
        status 'httperror' to be returned.
        """
        self._set_errors_in_config('')

        # Test request httperror 444
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': 444,
            }
        response = self._make_admin_request_custom_status('init', params, 444)

        self.assertEqual(_get_status_code(response), 444)
        self.assertEqual(response.content_type, 'text/html')
        self.assertIn("ERR1112: getUserResolverId failed", response)

        # Test request httperror emtpy
        params = {
            'user': 'doesnotexist',
            'type': 'spass',
            'genkey': 1,
            'httperror': '',
            }
        response = self._make_admin_request_custom_status('init', params, 500)

        self.assertEqual(_get_status_code(response), 500)
        self.assertEqual(response.content_type, 'text/html')
        self.assertIn("ERR1112: getUserResolverId failed", response)


    def test_httperror_and_invalid_utf8(self):
        """
        Return httperror even if params contain invalid UTF-8

        Invalid UTF-8 causes problems when LinOTP tries to process the request
        parameters. 'httperror' should still be honoured.

        C0 is an invalid UTF-8 byte sequence. See:
            http://en.wikipedia.org/wiki/UTF-8#Invalid_byte_sequences
        """
        if _webob_version() < LooseVersion('1.2'):
            self.skipTest(
                "Older WebOb versions don't raise UnicodeDecodeError in this "
                "scenario because internally errors='replace' is passed to the "
                "decode() method."
                )

        # Test request httperror 444
        params = {
            'user': 'doesnotexist\xc0',
            'type': 'spass',
            'genkey': 1,
            'httperror': 444,
            }
        response = self._make_admin_request_custom_status('init', params, 444)

        self.assertEqual(_get_status_code(response), 444)
        self.assertEqual(response.content_type, 'text/html')
        # Original error message (ERR1112: getUserResolverId failed...) is replaced
        self.assertIn(
            "-311: 'utf8' codec can't decode byte 0xc0 in position 12: invalid"
                " start byte",
            response
            )


    def test_no_httperror_and_invalid_utf8(self):
        """
        Return httperror even if params contain invalid UTF-8

        Invalid UTF-8 causes problems when LinOTP tries to process the request
        parameters.

        C0 is an invalid UTF-8 byte sequence. See:
            http://en.wikipedia.org/wiki/UTF-8#Invalid_byte_sequences
        """
        if _webob_version() < LooseVersion('1.2'):
            self.skipTest(
                "Older WebOb versions don't raise UnicodeDecodeError in this "
                "scenario because internally errors='replace' is passed to the "
                "decode() method."
                )

        # Test request no httperror
        params = {
            'user': 'doesnotexist\xc0',
            'type': 'spass',
            'genkey': 1,
            }
        response = self.make_admin_request('init', params)
        content = self.get_json_body(response)

        self.assertEqual(_get_status_code(response), 200)
        self.assertEqual(response.content_type, 'application/json')
        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertFalse(content['result']['status'])
        self.assertIn('error', content['result'])
        self.assertIn('message', content['result']['error'])
        self.assertIn('code', content['result']['error'])
        # ERR1112: getUserResolverId failed
        self.assertEqual(content['result']['error']['code'], -311)


    def _make_admin_request_custom_status(self, action, params, status):
        """
        Make authenticated 'admin' request with a custom HTTP status expected
        as response. By default self.app.get will raise an exception when
        something other and 2xx or 3xx is returned.
        """
        params.update({'session': self.session})
        headers = {
            'Authorization': TestController.get_http_digest_header(
                username='admin'
                ),
            }
        TestController.set_cookie(self.app, 'admin_session', self.session)

        return self.app.get(
            url(controller='admin', action=action),
            params=params,
            headers=headers,
            status=status,
            )


    def _del_errors_from_config(self):
        """
        Removes the 'errors' entry from LinOTP Config
        """
        params = {'key': 'errors'}
        response = self.make_system_request('delConfig', params)
        content = self.get_json_body(response)

        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertTrue(content['result']['status'])
        self.assertIn('value', content['result'])
        self.assertIn('delConfig errors', content['result']['value'])
        self.assertTrue(content['result']['value']['delConfig errors'])

    def _set_errors_in_config(self, errors):
        """
        Sets the 'errors' entry in LinOTP Config.

        :param errors: A string of comma-separated integers (e.g. '233,567')
        """
        params = {'errors': errors}
        response = self.make_system_request('setConfig', params)
        content = self.get_json_body(response)

        self.assertIn('result', content)
        self.assertIn('status', content['result'])
        self.assertTrue(content['result']['status'])
        self.assertIn('value', content['result'])
        self.assertIn('setConfig errors:%s' % errors, content['result']['value'])
        self.assertTrue(content['result']['value']['setConfig errors:%s' % errors])

