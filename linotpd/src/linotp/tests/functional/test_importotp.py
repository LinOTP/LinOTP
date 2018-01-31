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
"""
import json

from linotp.tests import TestController

import linotp.lib.ImportOTP

import os

class TestImportOTP(TestController):

    def setUp(self):
        TestController.setUp(self)

    def tearDown(self):
        """
        make the dishes
        """
        self.delete_all_policies()
        self.delete_all_token()

        return TestController.tearDown(self)

    def _get_file_name(self, data_file):
        """
        helper to read token data files
        """

        return os.path.join(self.fixture_path, data_file)

    def _read_data(self, data_file):
        """
        helper to read token data files
        """

        file_name = self._get_file_name(data_file)

        with open(file_name, "r") as data_file:

            data = data_file.read()

            return data

    def upload_tokens(self, file_name, data=None, params=None,
                      auth_user='admin'):
        """
        helper to upload a token file via admin/loadtokens file upload
        like it is done in the browser

        :param file_name: the name of the token file in the fixtures dir
        :param data: do not read the fixture file and use data instead
        :param params: additional parameters to describe the file type
        :return: the response from LinOTP
        """

        if data is None:
            data = self._read_data(file_name)

        upload_files = [("file", file_name, data)]

        response = self.make_admin_request('loadtokens',
                                           params=params,
                                           method='POST',
                                           upload_files=upload_files,
                                           auth_user=auth_user)

        return response

    def create_policy(self, params):
        name = params['name']
        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('setPolicy ' + name in response, response)
        return response

    def test_parse_DAT(self):
        '''
        Test to parse of eToken dat file format - import
        '''

        data = self._read_data("safework_tokens.dat")

        TOKENS = linotp.lib.ImportOTP.eTokenDat.parse_dat_data(data,
                                                               '1.1.2000')

        self.assertTrue(len(TOKENS) == 2, TOKENS)
        self.assertTrue(TOKENS.get("RAINER02") is not None, TOKENS)
        self.assertTrue(TOKENS.get("RAINER01") is not None, TOKENS)

        return

    def test_import_DAT(self):
        '''
        Test to import of eToken dat file format
        '''

        params = {
            'type':'dat',
            'startdate':'1.1.2000'}

        response = self.upload_tokens("safework_tokens.dat", params=params)

        # the response of the upload is an xml document like the following one
        #
        #    '<?xml version="1.0" encoding="UTF-8"?>'
        #    '<jsonrpc version="2.0">'
        #    '    <result>'
        #    '        <status>True</status>'
        #    '        <value><imported>2</imported><value>True</value></value>'
        #    '    </result>'
        #    '    <version>LinOTP 2.10.dev1</version>'
        #    '    <id>1</id>'
        #    '</jsonrpc>'

        self.assertTrue('<imported>2</imported>' in response.body, response)

        # ------------------------------------------------------------------ --

        # test for upload empty file data

        params = {
            'type':'dat',
            'startdate':'1.1.2000'}

        response = self.upload_tokens("safework_tokens.dat",
                                      data="",
                                      params=params)

        error_msg = 'Error loading tokens. File or Type empty'
        self.assertTrue(error_msg in response, response)

        # ------------------------------------------------------------------ --

        # test with data containing only comments
        data = "#"
        params = {
            'type': 'dat',
            'startdate': '1.1.2000'}

        response = self.upload_tokens("safework_tokens.dat",
                                      data=data,
                                      params=params)

        error_msg = '<imported>0</imported>'
        self.assertTrue(error_msg in response, response)

        # ------------------------------------------------------------------ --

        # test: no startdate

        params = {
            'file':data,
            'type':'dat'}

        response = self.upload_tokens("safework_tokens.dat",
                                      params=params)

        error_msg = '<imported>2</imported>'
        self.assertTrue(error_msg in response, response)

        # ------------------------------------------------------------------ --

        # test: wrong startdate

        params = {
            'type':'dat',
            'startdate': '2000-12-12', }

        response = self.upload_tokens("safework_tokens.dat",
                                      params=params)


        error_msg = '<imported>2</imported>'
        self.assertTrue(error_msg in response, response)

        return

    def test_parse_PSKC_OCRA(self):
        '''
        Test import OCRA via PSCK
        '''

        xml = self._read_data("ocra_pskc_tokens.xml")

        from linotp.lib.ImportOTP.PSKC import parsePSKCdata
        TOKENS = parsePSKCdata(xml,
                 preshared_key_hex="4A057F6AB6FCB57AB5408E46A9835E68",
                 do_checkserial=False)

        self.assertTrue(len(TOKENS) == 3, TOKENS)
        self.assertTrue(TOKENS.get("306EUO4-00954") is not None, TOKENS)
        self.assertTrue(TOKENS.get("306EUO4-00958") is not None, TOKENS)
        self.assertTrue(TOKENS.get("306EUO4-00960") is not None, TOKENS)

        return

    def test_parse_HOTP_PSKC(self):
        '''
        Test import HOTP via PSKC
        '''

        pskc_xml = self._read_data("pskc_tokens.xml")

        TOKENS = linotp.lib.ImportOTP.PSKC.parsePSKCdata(
                                                    pskc_xml,
                                                    do_checkserial=False)

        self.assertTrue(len(TOKENS) == 6, TOKENS)

        return

    def test_parse_Yubikey_CSV(self):
        '''
        Test the parsing of Yubikey CSV file
        '''

        csv = self._read_data("yubi_tokens.csv")

        TOKENS = linotp.lib.ImportOTP.parseYubicoCSV(csv)
        self.assertTrue(len(TOKENS) == 5, TOKENS)

        return

    def test_parse_XML(self):
        '''
        Test parse an SafeNet XML import
        '''
        xml = self._read_data("safenet_tokens.xml")

        TOKENS = linotp.lib.ImportOTP.parseSafeNetXML(xml)
        self.assertTrue(len(TOKENS) == 2, TOKENS)

        return

    def test_import_OATH(self):
        '''
        test to import token data
        '''

        params = {'type':'oathcsv'}

        response = self.upload_tokens("oath_tokens.csv", params=params)

        self.assertTrue('<imported>4</imported>' in response, response)

        return

    def test_import_OATH_256(self):
        '''
        test to import token data sha256 seeds
        '''

        params = {'type':'oathcsv'}

        response = self.upload_tokens("oath_tokens_sha256.csv", params=params)
        self.assertTrue('<imported>8</imported>' in response, response)

        # we use for testing the totp test vectors from
        # https://tools.ietf.org/html/rfc6238

        # 1. test token with explicit sha256
        # htok_sha256_3, 313233343536373839303 ... 9303132, hotp, 8 ,,sha256,

        params = {
            'serial': 'htok_sha256_3',
            'pass': '46119246'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": true' in response, response)

        # 2. test token with no explicit sha256 - determined by seed length
        # htok_sha256_1, 31323334353637383....03132, hotp,       8   ,

        params = {
            'serial': 'htok_sha256_1',
            'pass': '46119246'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": true' in response, response)

        # 3. positive test token - seed len for sha1 and sha1 otp
        # htok_sha1_6, 313233343...3031323334353637383930, hotp, 8, , , ,

        params = {
            'serial': 'htok_sha1_6',
            'pass': '94287082'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": true' in response, response)

        # 4. negative test token - seed len for sha1 but declared as sha256
        # htok_sha256_7, 3132333435...1323334353637383930, hotp, 8 ,, Sha256,

        params = {
            'serial': 'htok_sha256_7',
            'pass': '94287082'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": false' in response, response)

        return

    def test_import_OATH_512(self):
        '''
        test to import token data with sha512 seeds
        '''

        params = {'type':'oathcsv'}

        response = self.upload_tokens("oath_tokens_sha512.csv", params=params)
        self.assertTrue('<imported>8</imported>' in response, response)

        # we use for testing the totp test vectors from
        # https://tools.ietf.org/html/rfc6238

        # 1. test token with explicit sha512
        # htok_sha512_3, 313233343536373839303 ... 9303132, hotp, 8 ,,sha512,

        params = {
            'serial': 'htok_sha512_3',
            'pass': '90693936'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": true' in response, response)

        # 2. test token with no explicit sha512 - determined by seed length
        # htok_sha512_1, 31323334353637383....03132, hotp,       8   ,

        params = {
            'serial': 'htok_sha512_1',
            'pass': '90693936'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": true' in response, response)

        # 3. positive test token - seed len for sha1 and sha1 otp
        # htok_sha1_6, 313233343...3031323334353637383930, hotp, 8, , , ,

        params = {
            'serial': 'htok_sha1_6',
            'pass': '94287082'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": true' in response, response)

        # 4. negative test token - seed len for sha1 but declared as sha512
        # htok_sha512_7, 3132333435...1323334353637383930, hotp, 8 ,, Sha512,

        params = {
            'serial': 'htok_sha512_7',
            'pass': '94287082'}

        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": false' in response, response)

        return

    def test_import_PSKC(self):
        '''
        Test to import PSKC data
        '''

        params = {
            'type':'pskc',
            'pskc_type': 'plain',
            'pskc_password': "",
            'pskc_preshared': ""}

        response = self.upload_tokens("pskc_tokens.xml", params=params)

        self.assertTrue('<imported>6</imported>' in response, response)

        params = {
            'type':'pskc',
            'pskc_type': 'plain',
            'pskc_password': "",
            'pskc_preshared': "",
            'pskc_checkserial': 'true'}

        response = self.upload_tokens("pskc_tokens.xml", params=params)

        self.assertTrue('<imported>0</imported>' in response, response)

        return

    def test_import_empty_file(self):
        '''
        Test loading empty file
        '''

        params = {
            'type':'pskc',
            'pskc_type': 'plain',
            'pskc_password': "",
            'pskc_preshared': ""}

        response = self.upload_tokens('token.psk', data="", params=params)

        self.assertTrue('<status>False</status>' in response, response)
        self.assertTrue('Error loading tokens. File'
                        ' or Type empty!' in response, response)

        return

    def test_import_unknown(self):
        '''
        Test to import unknown type
        '''

        params = {'type':'XYZ'}
        response = self.upload_tokens("pskc_tokens.xml", params=params)

        self.assertTrue('<status>False</status>' in response, response)
        self.assertTrue('Unknown file type' in response, response)

        return

    def test_import_XML(self):
        '''
        Test to import XML data
        '''

        params = {'type':'aladdin-xml'}
        response = self.upload_tokens("safenet_tokens.dat", params=params)

        self.assertTrue('<imported>2</imported>' in response, response)

        return

    def test_import_Yubikey(self):
        '''
        Test to import Yubikey CSV
        '''

        params = {'type':'yubikeycsv'}
        response = self.upload_tokens("yubi_tokens.csv", params=params)

        self.assertTrue('<imported>5</imported>' in response, response)

        return

    def test_upload_token_into_targetrealm(self):
        '''
        Test the upload of the tokens into a target realm
        '''

        self.create_common_resolvers()
        self.create_common_realms()

        target_realm = 'mymixrealm'

        # ------------------------------------------------------------------ --

        # define policy

        params = {'scope': 'admin',
                  'action': '*',
                  'realm': '%s' % target_realm,
                  'user': '*',
                  'name': 'all_actions'}

        self.create_policy(params)

        # ------------------------------------------------------------------ --

        params = {
            'type': 'yubikeycsv',
            'targetrealm': target_realm}

        response = self.upload_tokens("yubi_chall_tokens.csv", params=params)

        self.assertTrue('<imported>3</imported>' in response, response)

        # ------------------------------------------------------------------ --

        # get defined tokens and lookup the token realms

        response = self.make_admin_request('show', params={})

        jresp = json.loads(response.body)
        tokens = jresp.get('result', {}).get('value', {}).get('data', [])

        self.assertTrue(len(tokens) == 3, jresp)

        for token in tokens:
            token_realms = token.get('LinOtp.RealmNames', [])
            self.assertTrue(target_realm in token_realms, token)

        self.delete_policy('all_actions')

        return

    def test_yubikey_challenge(self):
        '''
        Test yubikey in challenge response mode with policy
        '''

        self.create_common_resolvers()
        self.create_common_realms()

        params = {
            'type': 'yubikeycsv',
            'targetrealm': 'mymixrealm'}

        response = self.upload_tokens("yubi_chall_tokens.csv", params=params)

        self.assertTrue('<imported>3</imported>' in response, response)

        # ------------------------------------------------------------------ --

        # define policy

        params = {'scope': 'authentication',
                  'action': 'challenge_response=*,',
                  'realm': '*',
                  'user': '*',
                  'name': 'yubi_challenge'}

        self.create_policy(params)

        # ------------------------------------------------------------------ --

        # get defined tokens and assign them to a user

        response = self.make_admin_request('show', params={})

        jresp = json.loads(response.body)

        err_msg = "Error getting token list. Response %r" % (jresp)
        self.assertTrue(jresp['result']['status'], err_msg)

        # extract the token info

        serials = set()

        data = jresp['result']['value']['data']

        for entry in data:

            serial = entry['LinOtp.TokenSerialnumber']

            serials.add(serial)

            params = {'serial': serial,
                      'user': 'passthru_user1'}

            self.make_admin_request('assign', params=params)

            params = {'serial': serial,
                      'pin': '123!'}

            self.make_admin_request('set', params=params)

        # ------------------------------------------------------------------ --

        # trigger challenge and check that all yubi token have been triggered

        params = {'user': 'passthru_user1',
                  'pass': '123!'}

        response = self.make_validate_request('check', params=params)

        for serial in serials:

            self.assertTrue(serial in response, response)

        # ------------------------------------------------------------------ --

        # now we remove the policy and no challenge should be triggered

        params = {'name': 'yubi_challenge'}

        response = self.make_system_request('delPolicy', params=params)

        self.assertTrue('"status": true' in response, response)

        # ------------------------------------------------------------------ --

        # trigger challenge and check that no yubi token have been triggered

        params = {'user': 'passthru_user1',
                  'pass': '123!'}

        response = self.make_validate_request('check', params=params)

        for serial in serials:

            self.assertFalse(serial in response, response)

        return

    def test_import_OATH_with_admin_policy(self):
        '''
        test to import token with admin policies
        '''
        self.create_common_resolvers()
        self.create_common_realms()

        # 0. define access policy
        # * only for root and
        # * only in target realm: 'mydefrealm'

        params = {'scope': 'admin',
                  'action': 'import',
                  'realm': 'mydefrealm',
                  'user': 'admin',
                  'name': 'all_admin'}

        response = self.create_policy(params)
        self.assertTrue('"setPolicy all_admin"' in response.body, response)

        # ------------------------------------------------------------------ --

        # 1. negative test: hugo is not allowed to load tokens

        params = {
            'type':'oathcsv'}

        response = self.upload_tokens("oath_tokens.csv", params=params,
                                      auth_user='hugo')

        msg = "You do not have the administrative right to import tokens"
        self.assertTrue(msg in response.body, response)

        # ------------------------------------------------------------------ --

        # 2. negative test: as target realm only 'mydefrealm' is allowed

        params = {
            'type':'oathcsv',
            'targetrealm': 'myOtherRealm'}

        response = self.upload_tokens("oath_tokens.csv", params=params,
                                      auth_user='admin')

        msg = "target realm could not be assigned"
        self.assertTrue(msg in response.body, response)

        # ------------------------------------------------------------------ --

        # 3. positiv test: allowed target realm 'mydefrealm' for user 'admin'

        params = {
            'type':'oathcsv',
            'targetrealm': 'mydefrealm'}

        response = self.upload_tokens("oath_tokens.csv", params=params,
                                      auth_user='admin')

        self.assertTrue('<imported>4</imported>' in response, response)

        self.delete_policy('all_admin')

        self.delete_all_realms()
        self.delete_all_resolvers()

        return

# eof #
