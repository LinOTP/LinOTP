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
Test the 'httperror' parameter that is interpreted in
linotp.lib.reply.sendError()

This parameter allows a client to specify that he/she wants a custom HTTP
status code instead of a standard JSON 200 OK (with error description) response
in case of an error.
"""


import logging

from linotp.tests import TestController, url

log = logging.getLogger(__name__)


class TestHTTPError(TestController):
    def tearDown(self):
        self._del_errors_from_config()
        return TestController.tearDown(self)

    def test_no_httperror(self):
        """
        Default case: No httperror sent. Response is JSON 200 OK
        """
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
        }
        response = self.make_admin_request("init", params)
        content = response.json

        assert response.status == "200 OK"
        assert response.content_type == "application/json"
        assert "result" in content
        assert "status" in content["result"]
        assert not content["result"]["status"]
        assert "error" in content["result"]
        assert "message" in content["result"]["error"]
        assert "code" in content["result"]["error"]
        # ERR1112: getUserResolverId failed
        assert content["result"]["error"]["code"] == 1112

    def test_httperror(self):
        """
        Send 'httperror' in request and verify same HTTP status is returned.
        """
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": 444,
        }
        response = self._make_admin_request_custom_status("init", params, 444)

        assert "text/html" in response.content_type.split(";")
        assert "ERR1112: getUserResolverId failed" in response

    def test_empty_httperror(self):
        """
        Send empty 'httperror' in request and verify status 500 is returned.
        """
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": "",
        }
        response = self._make_admin_request_custom_status("init", params, 500)

        assert "text/html" in response.content_type.split(";")
        assert "ERR1112: getUserResolverId failed" in response

    def test_httperror_errid_in_config(self):
        """
        Verify httperror returned if errId in Config.errors

        If 'errors' in LinOTP Config is set, and the ID of the error that is
        raised (1112 in this case) is contained in that list, then a HTTP
        status 'httperror' is returned.
        """
        self._set_errors_in_config("233,567,1112")

        # Test request httperror 444
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": 444,
        }
        response = self._make_admin_request_custom_status("init", params, 444)

        assert "text/html" in response.content_type.split(";")
        assert "ERR1112: getUserResolverId failed" in response

        # Test request httperror empty
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": "",
        }
        response = self._make_admin_request_custom_status("init", params, 500)

        assert "text/html" in response.content_type.split(";")
        assert "ERR1112: getUserResolverId failed" in response

    def test_httperror_errid_not_in_config(self):
        """
        Verify httperror ignored if errId not in Config.errors

        If 'errors' in LinOTP Config is set, and the ID of the error that is
        raised (1112 in this case) is NOT in that list, then a regular JSON
        response is returned.
        """
        self._set_errors_in_config("233,567")

        # Test request httperror 444
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": 444,
        }
        response = self.make_admin_request("init", params)
        content = response.json

        assert response.content_type == "application/json"
        assert "result" in content
        assert "status" in content["result"]
        assert not content["result"]["status"]
        assert "error" in content["result"]
        assert "message" in content["result"]["error"]
        assert "code" in content["result"]["error"]
        # ERR1112: getUserResolverId failed
        assert content["result"]["error"]["code"] == 1112

        # Test request httperror empty
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": "",
        }
        response = self.make_admin_request("init", params)
        content = response.json

        assert response.content_type == "application/json"
        assert "result" in content
        assert "status" in content["result"]
        assert not content["result"]["status"]
        assert "error" in content["result"]
        assert "message" in content["result"]["error"]
        assert "code" in content["result"]["error"]
        # ERR1112: getUserResolverId failed
        assert content["result"]["error"]["code"] == 1112

    def test_no_httperror_with_config(self):
        """
        Presence of 'errors' in Config makes no difference without httperror

        Even if 'errors' in LinOTP Config is set, it makes no difference as
        long as no 'httperror' parameter is not sent in the request. A JSON 200
        OK response is returned.
        """
        self._set_errors_in_config("233,567")

        # Test request (no httperror)
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
        }
        response = self.make_admin_request("init", params)
        content = response.json

        assert response.content_type == "application/json"
        assert "result" in content
        assert "status" in content["result"]
        assert not content["result"]["status"]
        assert "error" in content["result"]
        assert "message" in content["result"]["error"]
        assert "code" in content["result"]["error"]
        # ERR1112: getUserResolverId failed
        assert content["result"]["error"]["code"] == 1112

    def test_httperror_and_config_set_but_empty(self):
        """
        If 'errors' in Config is empty 'httperror' triggers status httperror

        If 'errors' in LinOTP Config is set but empty all errIds cause HTTP
        status 'httperror' to be returned.
        """
        self._set_errors_in_config("")

        # Test request httperror 444
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": 444,
        }
        response = self._make_admin_request_custom_status("init", params, 444)

        assert "text/html" in response.content_type.split(";")
        assert "ERR1112: getUserResolverId failed" in response

        # Test request httperror emtpy
        params = {
            "user": "doesnotexist",
            "type": "spass",
            "genkey": 1,
            "httperror": "",
        }
        response = self._make_admin_request_custom_status("init", params, 500)

        assert "text/html" in response.content_type.split(";")
        assert "ERR1112: getUserResolverId failed" in response

    def test_httperror_and_invalid_utf8(self):
        """
        Return error response on httperror and invalid UTF-8 in params

        Invalid UTF-8 causes problems when LinOTP tries to process the request
        parameters. 'httperror' should still be honoured.

        C0 is an invalid UTF-8 byte sequence. See:
            http://en.wikipedia.org/wiki/UTF-8#Invalid_byte_sequences
        """
        # Test request httperror 444
        params = {
            "user": "doesnotexist\xc0",
            "type": "spass",
            "genkey": 1,
            "httperror": 444,
        }
        response = self._make_admin_request_custom_status("init", params, 444)

        assert "text/html" in response.content_type.split(";")
        assert "getUserId failed: no user >doesnotexist" in response.body

    def test_no_GET_for_admin_init(self):
        """
        it's not allowed to do modifying request as a GET request
        """

        # Test request no httperror
        params = {
            "type": "spass",
            "genkey": 1,
        }
        response = self.make_admin_request("init", params, method="GET")

        assert response.status == "405 METHOD NOT ALLOWED"

    def test_no_httperror_and_invalid_utf8(self):
        """
        Return error response on invalid UTF-8 in params without httperror

        Invalid UTF-8 causes problems when LinOTP tries to process the request
        parameters.

        C0 is an invalid UTF-8 byte sequence. See:
            http://en.wikipedia.org/wiki/UTF-8#Invalid_byte_sequences
        """

        # Test request no httperror
        params = {
            "user": "doesnotexist\xc0",
            "type": "spass",
            "genkey": 1,
        }
        response = self.make_admin_request("init", params, method="POST")
        content = response.json

        assert response.status == "200 OK"
        assert response.content_type == "application/json"
        assert "result" in content
        assert "status" in content["result"]
        assert not content["result"]["status"]
        assert "error" in content["result"]
        assert "message" in content["result"]["error"]
        assert "code" in content["result"]["error"]
        # ERR1112: getUserResolverId failed
        assert content["result"]["error"]["code"] == 1112

    def _make_admin_request_custom_status(self, action, params, status):
        """
        Make authenticated 'admin' request with a custom HTTP status expected
        as response. By default self.app.get will raise an exception when
        something other and 2xx or 3xx is returned.
        """
        response = self.make_admin_request(action, params)
        assert response.status_code == status

        return response

    def _del_errors_from_config(self):
        """
        Removes the 'errors' entry from LinOTP Config
        """
        params = {"key": "errors"}
        response = self.make_system_request("delConfig", params)
        content = response.json

        assert "result" in content
        assert "status" in content["result"]
        assert content["result"]["status"]
        assert "value" in content["result"]
        assert "delConfig errors" in content["result"]["value"]
        assert content["result"]["value"]["delConfig errors"]

    def _set_errors_in_config(self, errors):
        """
        Sets the 'errors' entry in LinOTP Config.

        :param errors: A string of comma-separated integers (e.g. '233,567')
        """
        params = {"errors": errors}
        response = self.make_system_request("setConfig", params)
        content = response.json

        assert "result" in content
        assert "status" in content["result"]
        assert content["result"]["status"]
        assert "value" in content["result"]
        assert "setConfig errors:%s" % errors in content["result"]["value"]
        assert content["result"]["value"]["setConfig errors:%s" % errors]
