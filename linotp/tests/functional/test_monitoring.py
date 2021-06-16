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
"""

import json
import logging

import pytest

from linotp.flap import config
from linotp.lib.support import (
    InvalidLicenseException,
    getSupportLicenseInfo,
    isSupportLicenseValid,
    readLicenseInfo,
    removeSupportLicenseInfo,
    setSupportLicenseInfo,
)
from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestMonitoringController(TestController):
    def setUp(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_license()

        super(TestMonitoringController, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        return

    def tearDown(self):
        super(TestMonitoringController, self).tearDown()

    # helper functions
    def checkCurrentLicense(self):
        """

        :return: 1 if license is available
                -1 if license is invalid
                0 if license is not available
        """
        try:
            # Test current license...
            getSupportLicenseInfo()
            return 1
        except InvalidLicenseException as err:
            if err.type != "UNLICENSED":
                # support license is invalid
                return -1
            else:
                # support license not available
                return 0

    def getCurrentLicense(self):
        # Test current license...
        lic, sig = getSupportLicenseInfo()
        isSupportLicenseValid(lic_dict=lic, lic_sign=sig, raiseException=True)
        return lic, sig

    def setCurrentLicense(self, old_lic, old_sig):
        if old_lic is None and old_sig is None:
            removeSupportLicenseInfo()
        else:
            setSupportLicenseInfo(old_lic, old_sig)

    def installLicense(self, licfile):
        new_lic, new_sig = readLicenseInfo(licfile)
        setSupportLicenseInfo(new_lic, new_sig)

    def create_token(
        self, serial="1234567", realm=None, user=None, active=True
    ):
        """
        create an HMAC Token with given parameters

        :param serial:  serial number, must be unique per token and test
        :param realm:   optional: set token realm
        :param user:    optional: assign token to user
        :param active:  optional: if this is False, token will be disabled
        :return: serial of new token
        """
        parameters = {
            "serial": serial,
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "description": "TestToken" + serial,
        }
        if realm:
            parameters["realm"] = realm
        if user:
            parameters["user"] = user

        response = self.make_authenticated_request(
            controller="admin", action="init", params=parameters
        )
        assert '"value": true' in response, response
        if active is False:
            response = self.make_authenticated_request(
                controller="admin", action="disable", params={"serial": serial}
            )

            assert '"value": 1' in response, response
        return serial

    # UnitTests...
    def test_config(self):
        response = self.make_authenticated_request(
            controller="monitoring", action="config", params={}
        )
        resp = json.loads(response.body)
        values = resp.get("result").get("value")
        assert values.get("realms") == 3, response
        assert values.get("passwdresolver") == 2, response
        # self.assertEqual(values.get('sync'), True, response)

        # provoke unsyncronized situation:
        self.make_authenticated_request(
            controller="monitoring", action="storageEncryption", params={}
        )
        response = self.make_authenticated_request(
            controller="monitoring", action="config", params={}
        )
        resp = json.loads(response.body)
        values = resp.get("result").get("value")
        assert values.get("realms") == 3, response
        assert values.get("passwdresolver") == 2, response
        # self.assertEqual(values.get('sync'), False, response)

        return

    def test_token_realm_list(self):
        self.create_token(serial="0001")
        self.create_token(serial="0002", user="root")
        self.create_token(serial="0003", realm="mydefrealm")
        self.create_token(serial="0004", realm="myotherrealm")
        # test what happens if first realm is empty:
        parameters = {"realms": ",mydefrealm,myotherrealm"}
        response = self.make_authenticated_request(
            controller="monitoring", action="tokens", params=parameters
        )
        resp = json.loads(response.body)
        values = resp.get("result").get("value")
        assert (
            values.get("Realms").get("mydefrealm").get("total") == 2
        ), response
        assert values.get("Summary").get("total") == 3, response
        return

    def test_token_active(self):

        policy_params = {
            "name": "test_token_active",
            "scope": "monitoring",
            "action": "tokens",
            "user": "*",
            "realm": "*",
        }
        self.create_policy(policy_params)

        self.create_token(serial="0011")
        self.create_token(serial="0012", user="root", active=True)
        self.create_token(serial="0013", realm="mydefrealm", active=True)
        self.create_token(serial="0014", realm="myotherrealm", active=False)

        parameters = {"realms": ",mydefrealm,myotherrealm", "status": "active"}
        response = self.make_authenticated_request(
            controller="monitoring", action="tokens", params=parameters
        )

        resp = json.loads(response.body)
        r_values = resp.get("result").get("value").get("Realms", {})

        # in the mydefrealm we have 2 active tokens, one belongs to an user

        mydefrealm = r_values.get("mydefrealm", {})
        assert mydefrealm.get("total", -1) == 2, response
        assert mydefrealm.get("total users", -1) == 1, response
        assert mydefrealm.get("active", -1) == 2, response

        # in the myotherrealm we have 1 inactive tokens, belongs to no one

        myotherrealm = r_values.get("myotherrealm", {})
        assert myotherrealm.get("total", -1) == 1, response
        assert myotherrealm.get("total users", -1) == 0, response
        assert myotherrealm.get("active", -1) == 0, response

        # in summary for myotherrealm and mydefrealm we have:
        #  2 inactive tokens, 1 token belongs to an user and 3 tokens

        s_values = resp.get("result").get("value").get("Summary", {})
        assert s_values.get("total", -1) == 3, response
        assert s_values.get("total users", -1) == 1, response
        assert s_values.get("active", -1) == 2, response

        return

    def test_token_status_combi(self):
        self.create_token(serial="0021")
        self.create_token(serial="0022", user="root")
        self.create_token(serial="0023", realm="mydefrealm")
        self.create_token(serial="0024", realm="myotherrealm")
        self.create_token(serial="0025", realm="myotherrealm", active=False)
        self.create_token(
            serial="0026", realm="myotherrealm", user="max2", active=False
        )
        parameters = {
            "realms": "mydefrealm,myotherrealm",
            "status": "unassigned&inactive",
        }
        response = self.make_authenticated_request(
            controller="monitoring", action="tokens", params=parameters
        )

        resp = json.loads(response.body)
        values = resp.get("result").get("value").get("Realms")

        assert values.get("mydefrealm").get("total", -1) == 2, response

        assert values.get("myotherrealm").get("total", -1) == 3, response

        assert (
            values.get("myotherrealm").get("unassigned&inactive", -1) == 1
        ), response

        assert (
            values.get("mydefrealm").get("unassigned&inactive", -1) == 0
        ), response

        s_values = resp.get("result").get("value").get("Summary")
        assert s_values.get("total", -1) == 5, response

        return

    def test_token_in_multiple_realms(self):
        """
        test the handling of token in multiple realms
        """
        sqlconnect = self.app.config.get("DATABASE_URI")
        if sqlconnect.startswith(("mysql", "sqlite")):
            pytest.xfail("monitoring query problem LINOTP-1540")

        # create some tokens

        self.create_token(serial="0041")
        self.create_token(serial="0042", user="root", realm="mydefrealm")

        # set multiple realms for this token

        newrealms = {"realms": "myotherrealm,mydefrealm", "serial": "0042"}
        response = self.make_authenticated_request(
            controller="admin", action="tokenrealm", params=newrealms
        )
        assert '"value": 1' in response, response

        # create some tokens but only in dedicated realms

        self.create_token(serial="0043", realm="mydefrealm")
        self.create_token(serial="0044", realm="myotherrealm")

        # now get the numbers by look at the monitoring
        # which should show 2 tokens in each realm but only 3 tokens in sum

        parameters = {"realms": "mydefrealm,myotherrealm"}

        response = self.make_authenticated_request(
            controller="monitoring", action="tokens", params=parameters
        )

        values = json.loads(response.body).get("result").get("value")

        assert values.get("Realms").get("mydefrealm").get("total") == 2
        assert values.get("Realms").get("myotherrealm").get("total") == 2
        assert values.get("Summary").get("total") == 3, response.body

        return

    def test_nolicense(self):
        """"""
        old_lic = None
        old_sig = None
        try:
            old_lic, old_sig = self.getCurrentLicense()

        except InvalidLicenseException as exx:
            if (
                str(exx) != "Support not available, your product is"
                " unlicensed"
            ):
                raise exx
        try:
            # Remove previous license...
            self.setCurrentLicense(None, None)

            response = self.make_authenticated_request(
                controller="monitoring", action="license", params={}
            )
            resp = json.loads(response.body)
            value = resp.get("result").get("value")
            assert value.get("valid") == False, response

        finally:
            # restore previous license...
            if old_lic and old_sig:
                self.setCurrentLicense(old_lic, old_sig)
        return

    def test_license(self):
        old_lic = None
        old_sig = None
        try:
            old_lic, old_sig = self.getCurrentLicense()
        except InvalidLicenseException as exx:
            if (
                str(exx) != "Support not available, your product is "
                "unlicensed"
            ):
                raise exx

        try:
            # Load the license file...
            licfile = config.get("monitoringTests.licfile", "")

            if not licfile:
                self.skipTest(
                    "Path to test license file is not configured, "
                    "check your configuration (test.ini)!"
                )

            lic_dict, lic_sig = readLicenseInfo(licfile)

            self.installLicense(licfile)

            self.create_token(serial="0031")
            self.create_token(serial="0032", user="root")
            self.create_token(serial="0033", realm="mydefrealm")
            self.create_token(serial="0034", realm="myotherrealm")
            self.create_token(
                serial="0035", realm="myotherrealm", active=False
            )
            self.create_token(
                serial="0036", realm="myotherrealm", user="max2", active=False
            )

            response = self.make_authenticated_request(
                controller="monitoring", action="license", params={}
            )
            resp = json.loads(response.body)
            value = resp.get("result").get("value")
            assert value.get("token-num") == int(
                lic_dict.get("token-num")
            ), response
            token_left = int(lic_dict.get("token-num")) - 4
            assert value.get("token-left") == token_left, response

        finally:
            # restore previous license...
            if old_lic and old_sig:
                self.setCurrentLicense(old_lic, old_sig)

        return

    def test_check_encryption(self):
        # do this test befor test_config
        response = self.make_authenticated_request(
            controller="monitoring", action="storageEncryption", params={}
        )
        resp = json.loads(response.body)
        values = resp.get("result").get("value")
        assert values.get("encryption"), response
        assert values.get("cryptmodul_name") == "Default", response
        assert (
            values.get("cryptmodul_type") == "DefaultSecurityModule"
        ), response

        # and one more time:
        response = self.make_authenticated_request(
            controller="monitoring", action="storageEncryption", params={}
        )
        resp = json.loads(response.body)
        values = resp.get("result").get("value")
        assert values.get("encryption"), response

    def test_userinfo(self):
        response = self.make_authenticated_request(
            controller="monitoring", action="userinfo", params={}
        )
        resp = json.loads(response.body)
        myotherrealm = (
            resp.get("result").get("value").get("Realms").get("myotherrealm")
        )
        assert myotherrealm.get("myOtherRes") == 8, response
        mymixrealm = (
            resp.get("result").get("value").get("Realms").get("mymixrealm")
        )
        assert mymixrealm.get("myOtherRes") == 8, response
        assert mymixrealm.get("myDefRes") == 27, response

    def test_userinfo_policy(self):
        # set policy:
        policy_params = {
            "name": "test_userinfo_policy",
            "scope": "monitoring",
            "action": "userinfo",
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }
        self.create_policy(policy_params)

        response = self.make_authenticated_request(
            controller="monitoring", action="userinfo", params={}
        )
        resp = json.loads(response.body)
        myotherrealm = (
            resp.get("result").get("value").get("Realms").get("myotherrealm")
        )
        assert myotherrealm is None
        mymixrealm = (
            resp.get("result").get("value").get("Realms").get("mymixrealm")
        )
        assert mymixrealm.get("myOtherRes") == 8, response
        assert mymixrealm.get("myDefRes") == 27, response

    def test_active_users(self):
        # mydefrealm = mydefresolver
        self.create_token(serial="0051", user="aἰσχύλος")
        self.create_token(serial="0052", user="aἰσχύλος")
        self.create_token(serial="0053", user="passthru_user1")
        self.create_token(serial="0054", user="root")
        self.create_token(serial="0055", user="susi")
        self.create_token(serial="0056", user="susi")
        self.create_token(serial="0057", user="shakespeare")
        # myotherrealm = myotherresolver
        self.create_token(serial="0058", user="max1@myotherrealm")
        self.create_token(serial="0059", user="max2", realm="myotherrealm")
        self.create_token(
            serial="0060", user="other_user", realm="myotherrealm"
        )
        self.create_token(
            serial="0061", user="other_user", realm="myotherrealm"
        )
        self.create_token(serial="0062", user="root", realm="myotherrealm")
        # mymixrealm = both resolvers
        self.create_token(serial="0063", user="susi", realm="mymixrealm")
        self.create_token(serial="0064", user="max1", realm="mymixrealm")

        response = self.make_authenticated_request(
            controller="monitoring", action="activeUsers", params={}
        )
        resp = json.loads(response.body)
        assert resp.get("result").get("value").get("total") == 9, response
        mydefrealm = (
            resp.get("result").get("value").get("Realms").get("mydefrealm")
        )
        assert mydefrealm.get("myDefRes") == 5, response
        myotherrealm = (
            resp.get("result").get("value").get("Realms").get("myotherrealm")
        )
        assert myotherrealm.get("myOtherRes") == 4, response
        mymixrealm = (
            resp.get("result").get("value").get("Realms").get("mymixrealm")
        )
        assert mymixrealm.get("myOtherRes") == 1, response
        assert mymixrealm.get("myDefRes") == 1, response


# eof ########################################################################
