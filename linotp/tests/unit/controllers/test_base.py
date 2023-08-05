# -*- coding: utf-8 -*-
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

""" test for json body as request parameters """

import copy
import unittest

import pytest
from mock import mock
from werkzeug.datastructures import CombinedMultiDict, MultiDict

import flask

from linotp.controllers.base import BaseController


@pytest.mark.usefixtures("app")
class TestBaseController(object):
    """
    test for request parameter handling to support parameters from json body
    """

    @mock.patch(
        "linotp.controllers.BaseController.__init__", return_value=None
    )
    def test_multidict_params(self, _mock_base, base_app):
        """
        check if global request.params gets parsed to a plain dict correctly
        """

        input_params = CombinedMultiDict(
            (MultiDict([("k[]", "1"), ("k[]", "2"), ("l", "Z")]),)
        )
        expected_params = {"k": ["1", "2"], "l": "Z"}

        controller = BaseController("test")

        with base_app.test_request_context(
            "/test",
            query_string=input_params,
            content_type="application/x-www-form-urlencoded",
        ):
            assert isinstance(
                controller.request_params, dict
            ), "self.request_params is not of type dict!"

            assert (
                controller.request_params == expected_params
            ), "parsed request_params do not match"

    @mock.patch(
        "linotp.controllers.BaseController.__init__", return_value=None
    )
    def test_jsondict_params(self, _mock_base, base_app):
        """
        check if global request.json_body gets parsed correctly
        """

        expected_params = {"k": ["1", "2"], "l": "Z"}

        controller = BaseController("test")

        with base_app.test_request_context(
            json=expected_params,
        ):
            assert isinstance(
                controller.request_params, dict
            ), "self.request_params is not of type dict!"

            assert (
                controller.request_params == expected_params
            ), "parsed request_params do not match"

    @mock.patch(
        "linotp.controllers.BaseController.__init__", return_value=None
    )
    def test_both_given(self, _mock_base, base_app):
        """
        check if json is give as content type the other params are ignored
        """

        expected_params = {"k": ["1", "2"], "l": "Z"}

        controller = BaseController("test")

        with base_app.test_request_context(
            "/test",
            query_string=expected_params,
            json=expected_params,
        ):
            assert isinstance(
                controller.request_params, dict
            ), "self.request_params is not of type dict!"

            assert (
                controller.request_params == expected_params
            ), "parsed request_params do not match"
