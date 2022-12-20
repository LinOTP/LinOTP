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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


"""
Testing the set license
"""

import os
import logging
import json

from mock import patch
from nose.tools import raises

from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time

from linotp.tests import TestController

import linotp.lib.support
from linotp.lib.support import InvalidLicenseException


log = logging.getLogger(__name__)


class TestSupport(TestController):

    def setUp(self):
        params = {'key': 'license'}
        response = self.make_system_request('delConfig', params)
        msg = '"delConfig license": true'
        self.assertTrue(msg in response)

        params = {'key': 'license_duration'}
        response = self.make_system_request('delConfig', params)
        msg = '"delConfig license_duration": true'
        self.assertTrue(msg in response)

        return TestController.setUp(self)

    def test_demo_license_expiration(self):
        """
        text that the demo license expires after 14 days
        """

        demo_license_file = os.path.join(self.fixture_path, "demo-lic.pem")
        with open(demo_license_file, "r") as f:
            demo_license = f.read()
        upload_files = [("license", "demo-lic.pem", demo_license)]

        two_weeks_ago = datetime.now() - timedelta(days=15)

        with freeze_time(two_weeks_ago):
            response = self.make_system_request("setSupport",
                                                upload_files=upload_files)
            self.assertTrue('"status": true' in response)
            self.assertTrue('"value": true' in response)

        response = self.make_system_request("getSupportInfo")
        jresp = json.loads(response.body)
        expiry = jresp.get("result", {}).get("value", {}).get("expire")
        expiry_date = datetime.strptime(expiry, "%Y-%m-%d")

        # check that the license expiration date is before today
        self.assertTrue(expiry_date < datetime.now())

        response = self.make_system_request("isSupportValid")
        jresp = json.loads(response.body)

        self.assertFalse(jresp.get("result", {}).get("value"))
        self.assertTrue("License expired" in jresp.get(
                                                    "detail", {}).get(
                                                        "reason"))

        return

    def test_set_expires_license(self):
        """
        check that installation of expired license fails
        """

        exp_license_file = os.path.join(self.fixture_path, "expired-lic.pem")
        with open(exp_license_file, "r") as f:
            exp_license = f.read()
        upload_files = [("license", "demo-lic.pem", exp_license)]

        response = self.make_system_request("setSupport",
                                            upload_files=upload_files)

        self.assertTrue('"status": false' in response)
        self.assertTrue("expired - valid till '2017-12-12'" in response)

        return

    def test_set_license_fails(self):
        """
        check that license could not be installed if too many tokens are used
        """

        for i in range(1,10):
            params = {
                'type': 'hmac',
                'genkey': 1,
                'serial': 'HMAC_DEMO%d' % i
                }
            response = self.make_admin_request('init', params)
            self.assertTrue('"status": true' in response)
            self.assertTrue('"value": true' in response)

        demo_license_file = os.path.join(self.fixture_path, "demo-lic.pem")
        with open(demo_license_file, "r") as f:
            demo_license = f.read()
        upload_files = [("license", "demo-lic.pem", demo_license)]

        response = self.make_system_request("setSupport",
                                            upload_files=upload_files)
        msg = "volume exceeded: tokens used: 9 > tokens supported: 5"
        self.assertTrue(msg in response)

    def test_appliance_demo_licence(self):
        """
        verify that if we are running on a sva2, the demo license is installed
        """

        # ------------------------------------------------------------------ --

        # first determin if the module support provides the function
        # running_on_appliance

        requires_patch = False
        if "running_on_appliance" in dir(linotp.lib.support):
            requires_patch = True

        # ------------------------------------------------------------------ --

        # depending on the existance of the function we must patch it or not

        if not requires_patch:
            return self.check_appliance_demo_licence()

        with patch("linotp.controllers.system."
                   "running_on_appliance") as mocked_running_on_appliance:

            mocked_running_on_appliance.return_value = True
            return self.check_appliance_demo_licence()

    def check_appliance_demo_licence(self):
        """
        helper test which is called mocked or unmocked
        """

        # ------------------------------------------------------------------ --

        # check that there is no license installed

        params = {'key': 'license'}
        response = self.make_system_request('getConfig', params)
        self.assertTrue('"getConfig license": null' in response)

        response = self.make_system_request("isSupportValid")

        if "your product is unlicensed" in response:
            raise InvalidLicenseException("your product is unlicensed")

        self.assertTrue('"status": true' in response)
        self.assertTrue('"value": true' in response)

        # ------------------------------------------------------------------ --

        # now check that the demo license with expiry in +14 day is installed

        response = self.make_system_request("getSupportInfo")
        jresp = json.loads(response.body)
        expiry = jresp.get("result", {}).get("value", {}).get("expire")

        expiry_date = datetime.strptime(expiry, "%Y-%m-%d")
        expected_expiry = datetime.now() + timedelta(days=14)

        self.assertTrue(expiry_date.year == expected_expiry.year)
        self.assertTrue(expiry_date.month == expected_expiry.month)
        self.assertTrue(expiry_date.day == expected_expiry.day)

        return


# eof ########################################################################
