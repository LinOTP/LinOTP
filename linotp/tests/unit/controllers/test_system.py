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

import unittest

import pytest
from flask import appcontext_pushed
from mock import patch

from linotp.controllers.system import SystemController
from linotp.flap import tmpl_context as context
from linotp.lib.security.provider import SecurityProvider
from linotp.model import db


@pytest.mark.usefixtures("app")
class TestSetResolver(unittest.TestCase):
    @patch("linotp.controllers.system.BaseController.__init__", return_value=None)
    def setUp(self, mock_base):
        unittest.TestCase.setUp(self)
        self.system = SystemController()

    def tearDown(self):
        db.session.remove()

    @patch("linotp.controllers.system.getResolverList", return_value=[])
    @patch("linotp.app.request")
    @patch("linotp.controllers.system.prepare_resolver_parameter")
    @patch("linotp.controllers.system._")
    @patch("linotp.controllers.system.defineResolver")
    def set_resolver(
        self,
        params,
        mock_define_resolver,
        mock_translate,
        mock_prepare,
        mock_request,
        mock_resolverlist,
    ):
        # Call set resolver with given parameters

        params["name"] = "UnitTestResolver"

        # prepare_request_params simply returns the parameters unchanged
        mock_prepare.side_effect = lambda new_resolver_name, param, previous_name: (
            param,
            False,
            False,
        )

        with patch("linotp.controllers.system.sendError") as mock_senderror:
            with patch("linotp.controllers.system.sendResult") as mock_sendresult:
                # sendError returns the exception
                mock_senderror.side_effect = lambda exx: exx
                mock_sendresult.side_effect = lambda obj, *args: obj
                mock_request.json = params
                ret = self.system.setResolver()

        return ret

    def test_set_resolver_readonly_param_invalid(self):
        expected_message = (
            "Failed to convert attribute 'readonly' to a boolean value! 'truly'"
        )
        ret = self.set_resolver({"readonly": "truly"})
        assert str(ret) == expected_message

    def test_set_resolver_readonly_param_empty(self):
        ret = self.set_resolver({"readonly": ""})
        assert ret, (
            "setResolver with empty readonly parameter should succeed. Returned:%s"
            % ret
        )


@pytest.fixture
def err_hsm(app, monkeypatch):
    """
    An HSM object that answers with not ready for testing exception conditions
    """

    def getErrSecurityModule(s):
        class ErrHSM(object):
            def isReady(self):
                return False

        return {"obj": ErrHSM()}

    # Override SecurityProvider.getSecurityModule() to return the error HSM
    monkeypatch.setattr(SecurityProvider, "getSecurityModule", getErrSecurityModule)


@pytest.mark.usefixtures("err_hsm")
class TestHSMFail(object):
    """
    Tests for #2909 to check behaviour with an HSM
    in error state
    """

    def test_hsm_exception(self, adminclient):
        """
        Test #2909: HSM problems will raise an HSM Exception
               which could trigger an HTTP Error
        """
        param = {"key": "sec", "value": "mySec", "type": "password"}

        response = adminclient.post("/system/setConfig", json=param)
        assert response.status_code == 200

        result = response.json["result"]
        assert result["status"] == False
        assert result["error"]["code"] == 707
        assert "hsm not ready" in result["error"]["message"]

    def test_httperror(self, adminclient):
        """
        Test that custom error code is returned if requested
        """
        param = {
            "key": "sec",
            "value": "mySec",
            "type": "password",
            "httperror": "503",
        }

        response = adminclient.post("/system/setConfig", json=param)
        assert response.status_code == 503
