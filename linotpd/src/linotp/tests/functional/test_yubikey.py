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

    serials = set()

    def init_token(self, serialnum="01382015",
                   yubi_slot=1,
                   otpkey="9163508031b20d2fbb1868954e041729",
                   public_uid="ecebeeejedecebeg"):
        serial = "UBAM%s_%s" % (serialnum, yubi_slot)

        parameters = {
            'type': 'yubikey',
            'serial': serial,
            'otpkey': otpkey,
            'otplen': 48,
            'description': "Yubikey enrolled in functional tests"
        }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, "Response: %r" % response)
        ## test initial assign
        parameters = {"serial": serial, "user": "root" }
        response = self.app.get(url(controller='admin', action='assign'),
                                params=parameters)
        # Test response...
        self.assertTrue('"value": true' in response, "Response: %r" % response)

        self.valid_otps = [
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

        self.serials.add(serial)
        return serial

    def test_yubico_mode(self):
        """
        Enroll and test the Yubikey in yubico (AES) mode
        """
        public_uid = "ecebeeejedecebeg"

        serial = self.init_token(public_uid=public_uid)

        for otp in self.valid_otps:
            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': serial, 'pass': otp})
            self.assertTrue('"value": true' in response, "Response: %r" % response)

        # Repeat an old (therefore invalid) OTP value
        invalid_otp = public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        response = self.app.get(url(controller='validate', action='check_s'),
                                params={'serial': serial, 'pass': invalid_otp})
        self.assertTrue('"value": false' in response, "Response: %r" % response)

        return


    def test_yubico_resync(self):
        """
        Enroll and resync the Yubikey
        """
        public_uid = "ecebeeejedecebeg"

        serial = self.init_token(public_uid=public_uid)

        otp1 = self.valid_otps[-2]
        otp2 = self.valid_otps[-1]

        response = self.app.get(url(controller='admin', action='resync'),
                                params={'serial': serial,
                                        'otp1': otp1,
                                        'otp2': otp2, })
        self.assertTrue('"value": true' in response, "Response: %r" % response)

        response = self.app.get(url(controller='admin', action='resync'),
                                params={'serial': serial,
                                        'otp1': otp1,
                                        'otp2': otp2, })
        self.assertTrue('"value": false' in response, "Response: %r" % response)

        return


    def tearDown(self):
        for serial in self.serials:
            self.removeTokenBySerial(serial)
        TestController.tearDown(self)
