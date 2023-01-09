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


""" used to do testing of the radius token"""

import logging

import pyrad.packet
import pyrad.server
from mock import patch
from pyrad.client import Client

from linotp.tests import TestController

log = logging.getLogger(__name__)

DEFAULT_NOSE_CONFIG = {
    "radius": {
        "authport": "18012",
        "acctport": "18013",
    }
}


class RadiusReponse(Client):
    def __init__(self, code=pyrad.packet.AccessAccept):
        self.code = code


def mocked_SendPacket_accept(rad_client, *argparams, **kwparams):
    """mock the radius accept response"""
    response = RadiusReponse(code=pyrad.packet.AccessAccept)
    return response


def mocked_SendPacket_reject(rad_client, *argparams, **kwparams):
    """mock the radius accept response"""
    response = RadiusReponse(code=pyrad.packet.AccessReject)
    return response


def mocked_SendPacket_error(rad_client, *argparams, **kwparams):
    """mock the radius accept response"""
    raise pyrad.server.ServerPacketError("bad packet")


class TestRadiusToken(TestController):

    p = None

    def setUp(self):

        self.radius_authport = DEFAULT_NOSE_CONFIG["radius"]["authport"]
        self.radius_acctport = DEFAULT_NOSE_CONFIG["radius"]["acctport"]

        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        # cleanup from last run
        try:
            self.deleteRadiusToken()
        except AssertionError:
            pass

        self.create_radius_token()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def create_radius_token(self):
        # The token with the remote PIN
        parameters1 = {
            "serial": "radius1",
            "type": "radius",
            "otpkey": "1234567890123456",
            "otppin": "",
            "user": "remoteuser",
            "pin": "pin",
            "description": "RadiusToken1",
            "radius.server": "localhost:%s" % self.radius_authport,
            "radius.local_checkpin": 0,
            "radius.user": "user_with_pin",
            "radius.secret": "testing123",
        }

        # the token with the local PIN
        parameters2 = {
            "serial": "radius2",
            "type": "radius",
            "otpkey": "1234567890123456",
            "otppin": "local",
            "user": "localuser",
            "pin": "pin",
            "description": "RadiusToken2",
            "radius.server": "localhost:%s" % self.radius_authport,
            "radius.local_checkpin": 1,
            "radius.user": "user_no_pin",
            "radius.secret": "testing123",
        }

        response = self.make_admin_request("init", params=parameters1)
        assert '"value": true' in response, response

        response = self.make_admin_request("init", params=parameters2)
        assert '"value": true' in response, response

        params = {"serial": "radius2", "pin": "local"}
        response = self.make_admin_request("set", params=params)
        assert '"set pin": 1' in response, response

        params = {"serial": "radius1", "pin": ""}
        response = self.make_admin_request("set", params=params)
        assert '"set pin": 1' in response, response

    def deleteRadiusToken(self):
        for serial in ["radius1", "radius2"]:
            parameters = {"serial": serial}
            response = self.make_admin_request("remove", params=parameters)
            assert '"value": 1' in response, response
            return

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_accept)
    def test_02_check_token_local_pin(self):
        """
        Checking if token with local PIN works
        """
        parameters = {"user": "localuser", "pass": "local654321"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": true' in response, response

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_accept)
    def test_03_check_token_remote_pin(self):
        """
        Checking if remote PIN works
        """
        parameters = {"user": "remoteuser", "pass": "test123456"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": true' in response, response

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_reject)
    def test_04_check_token_local_pin_fail(self):
        """
        Checking if a missing local PIN will fail
        """
        parameters = {"user": "localuser", "pass": "654321"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": false' in response, response

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_reject)
    def test_05_check_token_local_pin_fail2(self):
        """
        Checking if a wrong local PIN will fail
        """
        parameters = {"user": "localuser", "pass": "blabla654321"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": false' in response, response

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_reject)
    def test_06_check_token_remote_pin_fail(self):
        """
        Checking if a missing remote PIN will fail
        """
        parameters = {"user": "remoteuser", "pass": "123456"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": false' in response, response

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_reject)
    def test_06_check_token_remote_pin_fail2(self):
        """
        Checking if a wrong remote PIN will fail
        """
        parameters = {"user": "remoteuser", "pass": "abcd123456"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": false' in response, response

    @patch.object(pyrad.client.Client, "SendPacket", mocked_SendPacket_error)
    def test_07_check_token_remote_pin_fail2(self):
        """
        Checking if a wrong remote PIN will fail
        """
        parameters = {"user": "remoteuser", "pass": "abcd123456"}
        response = self.make_validate_request("check", params=parameters)
        assert '"value": false' in response, response


# eof##########################################################################
