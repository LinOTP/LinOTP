# -*- coding: utf-8 -*-
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
Testing the set license
"""

import os
import logging
import json

from nose.tools import raises

from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time

from linotp.tests import TestController


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
        
        


# eof ########################################################################
