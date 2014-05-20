# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
  Test the Yubikey.
"""

from linotp.tests import TestController, url


class TestYubikeyController(TestController):

    serial = None

    def test_yubico_mode(self):
        """
        Enroll and test the Yubikey in yubico (AES) mode
        """
        serialnum = "01382015"
        yubi_slot = 1
        self.serial = "UBAM%s_%s" % (serialnum, yubi_slot)
        otpkey = "9163508031b20d2fbb1868954e041729"
        parameters = {
            'type': 'yubikey',
            'serial': self.serial,
            'otpkey': otpkey,
            'otplen': 48,
            'description': "Yubikey enrolled in functional tests"
        }
        public_uid = "ecebeeejedecebeg"

        response = self.app.get(url(controller='admin', action='init'), params=parameters)
        self.assertTrue('"value": true' in response, "Response: %r" % response)
        ## test initial assign
        parameters = {"serial": self.serial, "user": "root" }
        response = self.app.get(url(controller='admin', action='assign'), params=parameters)
        # Test response...
        self.assertTrue('"value": true' in response, "Response: %r" % response)

        valid_otps = [
            public_uid + "fcniufvgvjturjgvinhebbbertjnihit",
            public_uid + "tbkfkdhnfjbjnkcbtbcckklhvgkljifu",
            public_uid + "ktvkekfgufndgbfvctgfrrkinergbtdj",
            public_uid + "jbefledlhkvjjcibvrdfcfetnjdjitrn",
            public_uid + "druecevifbfufgdegglttghghhvhjcbh",
            public_uid + "nvfnejvhkcililuvhntcrrulrfcrukll",
            public_uid + "kttkktdergcenthdredlvbkiulrkftuk",
            public_uid + "hutbgchjucnjnhlcnfijckbniegbglrt",
            public_uid + "vneienejjnedbfnjnnrfhhjudjgghckl",
            public_uid + "krgevltjnujcnuhtngjndbhbiiufbnki",
            public_uid + "kehbefcrnlfejedfdulubuldfbhdlicc",
            public_uid + "ljlhjbkejkctubnejrhuvljkvglvvlbk",
            public_uid + "eihtnehtetluntirtirrvblfkttbjuih",
        ]

        for otp in valid_otps:
            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serial, 'pass': otp})
            self.assertTrue('"value": true' in response, "Response: %r" % response)

        # Repeat an old (therefore invalid) OTP value
        invalid_otp = public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        response = self.app.get(url(controller='validate', action='check_s'),
                                params={'serial': self.serial, 'pass': invalid_otp})
        self.assertTrue('"value": false' in response, "Response: %r" % response)

    def tearDown(self):
        if self.serial:
            parameters = {'serial': self.serial}
            response = self.app.get(url(controller='admin', action='remove'), params=parameters)
            self.assertTrue('"value": 1' in response,
                            "Failed removing yubikey %s. Response: %s" % (self.serial, response))
        TestController.tearDown(self)
