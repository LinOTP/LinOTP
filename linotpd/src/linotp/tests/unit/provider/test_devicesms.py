# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
#
#    This file is part of LinOTP smsprovider.
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

import os
import sys
import unittest
import subprocess
from unittest import TestCase
from mock import MagicMock, Mock, patch

from linotp.provider.smsprovider.DeviceSMSProvider import DeviceSMSProvider
from linotp.lib import selftest

# BaseTestDeviceSMS contains tests to run which
# are independent of whether gnokii is installed.
# The actual testing is carried out in 2 subclasses
# corresponding to the separate situations
class BaseClass:
    class BaseTestDeviceSMS(TestCase):

        @classmethod
        def setUpClass(cls):
            super(BaseClass.BaseTestDeviceSMS, cls).setUpClass()

            cls.gnokii_available = False
            FNULL = open(os.devnull, 'w')
            try:
                ret = subprocess.call(["gnokii", "--version"], stdout=FNULL, stderr=FNULL)
                cls.gnokii_available = True
            except Exception as e:
                print e

        def setUp(self):
            self.default_config = {
                "CONFIGFILE": os.path.join(sys.path[0], "gnokiirc"),
                }
            self.phone = "1234567890"
            self.message = "123456"


        def do_send(self, config, expected_gnokii_status=0, phone=None, message=None):

            if phone:
                self.phone = phone
            if message:
                self.message = message

            sms = DeviceSMSProvider()
            sms.loadConfig(config)
            self.config = config

            if self.gnokii_available:
                wraps = subprocess.Popen
            else:
                wraps = None

            with patch('subprocess.Popen', wraps=wraps) as popen_mock:
                if not self.gnokii_available:
                    popen_mock.return_value.communicate.return_value = ("Mocked gnokii", "Status:%s" % expected_gnokii_status)
                    popen_mock.return_value.returncode = expected_gnokii_status
                self.return_code = sms.submitMessage(self.phone, self.message)
                if config.get("CONFIGFILE"):
                    self.assertEqual(popen_mock.call_count, 1, "SMS command should be called")
                    args, kwargs = popen_mock.call_args
                    self.gnokii_args = args
                else:
                    self.assertEqual(popen_mock.call_count, 0, "SMS command should not be called")

        def check_result(self, expected_result=True, expected_gnokii_call=True):

            self.assertEqual(expected_result, self.return_code, "Unexpected result from sms.submitMessage")

            if expected_gnokii_call:
                gnokki_cmd = "gnokii --config %s --sendsms %s" % (self.config["CONFIGFILE"], self.phone)

                if "SMSC" in self.config:
                    gnokki_cmd += " --smsc %s" % self.config["SMSC"]

                self.assertEqual(" ".join(self.gnokii_args[0]), gnokki_cmd)

        def test_01_default(self):
            self.do_send(self.default_config)
            self.check_result()

        def test_02_with_smsc(self):
            config = self.default_config.copy()
            config["SMSC"] = "+12345678"
            self.do_send(config)
            self.check_result()

        def test_03_missing_config(self):
            self.do_send({}, expected_gnokii_status=1)
            self.check_result(expected_result=False, expected_gnokii_call=False)

        def test_03_invalid_config(self):
            self.do_send({"CONFIGFILE": "12345"}, expected_gnokii_status=1)
            self.check_result(expected_result=False, expected_gnokii_call=True)

class TestWithoutGnokii(BaseClass.BaseTestDeviceSMS):
    def setUp(self):
        BaseClass.BaseTestDeviceSMS.setUp(self)

        # Always run without gnokii
        self.gnokii_available = False

class TestWithGnokii(BaseClass.BaseTestDeviceSMS):
    def setUp(self):
        BaseClass.BaseTestDeviceSMS.setUp(self)

        if self.gnokii_available == False:
            raise unittest.SkipTest("Gnokii is not available")



def main():
    unittest.main()

if __name__ == '__main__':
    main()
