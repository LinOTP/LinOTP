# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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

import json
from linotp.tests import TestController, url


class TestYubikeyController(TestController):

    serials = set()

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        for serial in self.serials:
            self.delete_token(serial)
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def init_otps(self, public_uid):
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
        return

    def init_token(self, serialnum="01382015",
                   yubi_slot=1,
                   otpkey="9163508031b20d2fbb1868954e041729",
                   public_uid="ecebeeejedecebeg",
                   use_public_id=False
                   ):
        serial = "UBAM%s_%s" % (serialnum, yubi_slot)

        params = {
            'type': 'yubikey',
            'serial': serial,
            'otpkey': otpkey,
            'description': "Yubikey enrolled in functional tests",
            'session': self.session
        }

        if not use_public_id:
            params['otplen'] = 32 + len(public_uid)
        else:
            params['public_uid'] = public_uid

        response = self.app.get(
            url(controller='admin', action='init'),
            params=params
            )
        self.assertTrue('"value": true' in response, "Response: %r" % response)

        # test initial assign
        params = {
            "serial": serial,
            "user": "root",
            'session': self.session,
            }
        response = self.app.get(
            url(controller='admin', action='assign'),
            params=params
            )
        # Test response...
        self.assertTrue('"value": true' in response, "Response: %r" % response)

        # setup the otp values, that we check against
        self.init_otps(public_uid)

        self.serials.add(serial)
        return serial

    def test_yubico_mode(self):
        """
        Enroll and verify otp for the Yubikey in yubico (AES) mode

        test with public_uid and without public_uid

        """
        public_uids = ["ecebeeejedecebeg", '']
        for public_uid in public_uids:

            serial = self.init_token(public_uid=public_uid)

            for otp in self.valid_otps:
                params = {'serial': serial, 'pass': otp}
                response = self.app.get(url(controller='validate',
                                            action='check_s'), params=params)
                self.assertTrue('"value": true' in response, "Response: %r"
                                % response)

            # Repeat an old (therefore invalid) OTP value
            invalid_otp = public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
            params = {'serial': serial, 'pass': invalid_otp}
            response = self.app.get(url(controller='validate',
                                        action='check_s'), params=params)
            self.assertTrue('"value": false' in response, "Response: %r"
                            % response)

        return

    def test_yubico_resync(self):
        """
        Enroll and resync the Yubikey
        """
        public_uid = "ecebeeejedecebeg"

        serial = self.init_token(public_uid=public_uid)

        otp1 = self.valid_otps[-2]
        otp2 = self.valid_otps[-1]

        params = {
            'serial': serial,
            'otp1': otp1,
            'otp2': otp2,
            'session': self.session,
            }
        response = self.app.get(
            url(controller='admin', action='resync'),
            params=params
            )
        self.assertTrue('"value": true' in response, "Response: %r" % response)

        params = {
            'serial': serial,
            'otp1': otp1,
            'otp2': otp2,
            'session': self.session,
            }
        response = self.app.get(
            url(controller='admin', action='resync'),
            params=params,
            )
        self.assertTrue('"value": false' in response, "Response: %r" % response)

        return

    def test_yubico_getSerialByOtp(self):
        """
        getSerialByOtp test for yubikey token w. and wo. prefix
        """
        public_uids = ["ecebeeejedecebeg", '']

        for public_uid in public_uids:

            # preserve the serial number for later check
            serial = self.init_token(public_uid=public_uid, use_public_id=True)
            for otp in self.valid_otps:
                params = {
                    'otp': otp,
                    'session': self.session,
                    }
                response = self.app.get(
                    url(controller='admin', action='getSerialByOtp'),
                    params=params,
                    )
                self.assertTrue('"status": true' in response,
                                "Response: %r" % response)

                # now access the data / serial number
                resp = json.loads(response.body)
                data = resp.get("result", {}).get('value', {})
                get_serial = data.get('serial')
                self.assertEqual(serial, get_serial, resp)

        return
