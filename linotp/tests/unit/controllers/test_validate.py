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

"""test for ValidateController"""

import logging

import pytest
from mock import mock

from linotp.controllers.validate import ValidateController
from linotp.lib.policy import AuthorizeException
from linotp.lib.user import User


class NotAuthorizeException(Exception):
    """This is an exception that is not an `AuthorizeException`. We use
    this because `validate.simplecheck()` differentiates between
    `AuthorizeException` and other exceptions.
    """

    pass


@pytest.mark.usefixtures("app")
class TestValidateController(object):
    @pytest.mark.parametrize(
        "check_rv,data",
        [
            ((True, {}), ":-)"),
            ((True, {"state": "foo"}), ":-) foo"),
            ((True, {"transactionid": "bar"}), ":-) bar"),
            ((True, {"state": "foo", "transactionid": "bar"}), ":-) bar"),
            ((True, {"data": "baz"}), ":-) baz"),
            ((True, {"message": "quux"}), ":-) quux"),
            ((True, {"data": "baz", "message": "quux"}), ":-) baz"),
            ((True, {"state": "foo", "data": "baz"}), ":-) foo baz"),
            ((False, {}), ":-("),
            (NotAuthorizeException("exception"), ":-("),
            (AuthorizeException, ":-("),
        ],
    )
    @mock.patch("linotp.controllers.validate.ValidateController._check")
    def test_simplecheck(self, _mock_check, client, check_rv, data, caplog):
        caplog.set_level(logging.INFO)
        if isinstance(check_rv, Exception):
            _mock_check.side_effect = check_rv
        else:
            _mock_check.return_value = check_rv

        response = client.get("/validate/simplecheck")
        assert response.status_code == 200
        assert response.data.decode() == data
        if isinstance(check_rv, AuthorizeException):
            assert "[simplecheck] validate/simplecheck: " in caplog.text
        elif isinstance(check_rv, NotAuthorizeException):
            assert "[simplecheck] failed: " in caplog.text
