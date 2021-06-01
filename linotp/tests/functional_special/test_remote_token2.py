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
used to do extended functional testing of the remote token
with focus on
- support of otppin policy support
- support of autoassignment
- support for yubikey as target token

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""

import json
import urllib.parse

import httplib2
from mock import patch

from linotp.tests.functional_special import TestSpecialController


# mocking hook is startting here
HTTP_RESPONSE_FUNC = None
HTTP_RESPONSE = None

def mocked_http_request(HttpObject, *argparams, **kwparams):

    resp = 200
    body = kwparams.get('body', '')
    params = dict(urllib.parse.parse_qsl(body))

    content = {
        "version": "LinOTP MOCK",
        "jsonrpc": "2.0",
        "result": {
            "status": True,
            "value": True
        },
        "id": 0
    }

    global HTTP_RESPONSE
    if HTTP_RESPONSE:
        status, response = HTTP_RESPONSE
        if response:
            content = response
            resp = status
        HTTP_RESPONSE = None

    global HTTP_RESPONSE_FUNC
    if HTTP_RESPONSE_FUNC:
        test_func = HTTP_RESPONSE_FUNC
        resp, content = test_func(params)
        HTTP_RESPONSE_FUNC = None

    return resp, json.dumps(content)




class TestRemoteToken2(TestSpecialController):

    def setUp(self):
        '''
        Overwrite the deleting of the realms!

        If the realms are deleted also the table TokenRealm gets deleted
        and we loose the information how many tokens are within a realm!
        '''
        TestSpecialController.setUp(self)
        self.remote_url = 'http://127.0.0.1:%s' % self.paster_port

        # Init the tests....
        self.delete_all_policies()
        self.delete_all_token()

        self.delete_all_realms()
        self.delete_all_resolvers()

        self.create_common_resolvers()
        self.create_realms()
        return

    def tearDown(self):
        ''' Overwrite parent tear down, which removes all realms '''
        return

    def create_pin_policies(self):

        # set the otppin=2 (no pin) for the 'nopin' realm
        p_name = 'nopin'

        params = {
               'name': p_name,
               'scope': 'authentication',
               'realm': 'nopin',
               'user': '*',
               'action': 'otppin=2',
               'client': '',
               'active': True
               }

        response = self.make_system_request('setPolicy', params=params)

        resp = json.loads(response.body)
        stat = resp.get('result', {}).get('value', {})\
                .get('setPolicy %s' % p_name, {})
        assert len(stat) > 0, response
        for val in list(stat.values()):
            assert val, response

        # set the otppin=1 (native) for the 'withpin' realm
        p_name = 'withpin'

        params = {
               'name': p_name,
               'scope': 'authentication',
               'realm': 'withpin',
               'user': '*',
               'action': 'otppin=1',
               'client': '',
               'active': True,
               }

        response = self.make_system_request('setPolicy', params=params)
        resp = json.loads(response.body)
        stat = resp.get('result', {}).get('value', {})\
                .get('setPolicy %s' % p_name, {})
        assert len(stat) > 0, response
        for val in list(stat.values()):
            assert val, response

        return

    def create_autoassign_policy(self):
        p_name = 'autoassignment_user'

        params = {
            'name': p_name,
            'scope': 'enrollment',
            'realm': 'nopin,withpin',
            'user': '*',
            'action': 'autoassignment=6',
            'active': True,
            'client': '',
            }

        response = self.make_system_request('setPolicy', params=params)

        resp = json.loads(response.body)
        stat = resp.get('result', {}).get('value', {})\
                .get('setPolicy %s' % p_name, {})
        assert len(stat) > 0, response
        for val in list(stat.values()):
            assert val, response

        return

    def create_autoassign_forward_policy(self):
        p_name = 'autoassignment_forward'

        params = {
            'name': p_name,
            'scope': 'enrollment',
            'realm': 'nopin,withpin',
            'user': '*',
            'action': 'autoassignment_forward',
            'active': True,
            'client': '',

            }

        response = self.make_system_request('setPolicy', params=params)

        resp = json.loads(response.body)
        stat = resp.get('result', {}).get('value', {})\
                .get('setPolicy %s' % p_name, {})
        assert len(stat) > 0, response
        for val in list(stat.values()):
            assert val, response
        return

    def init_remote_token(self, target_serial, target_otplen=6):
        """
        call admin/init to create the remote token

        :param target_serial: the serial number of the target token
        :param target_otplen: the otplen of the target token
        :return: the serial number of the remote token
        """

        serial = "LSRE%s" % target_serial,
        params = {
              "serial": serial,
              "type": "remote",
              "otplen": target_otplen,
              "description": "RemoteToken",
              'remote.server': self.remote_url,
              'remote.realm': 'nopin',
              'remote.local_checkpin': 1,
              'remote.serial': target_serial,
            }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, "Response: %r" % response

        return serial

    def init_yubi_token(self, serialnum="01382015", yubi_slot=1,
                        public_uid="ecebeeejedecebeg", use_public_id=False):
        """
        :param serialnum: define the serial id
        :param yubi_slot: the slot of the yubikey (part of the serial)
        :param public_uid: the prefix of the yubikey values
        :param use_public_id: as token init parameter the public_uid could
                              be used, if not used the otplen parameter is
                              required
        :return: - nothing -
        """

        otpkey = "9163508031b20d2fbb1868954e041729",

        self.yubi_valid_otps = [
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

        # local yubikey token
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

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, "Response: %r" % response

        return serial

    def create_realms(self):
        # define new realms: nopin and withpin
        resolvers = self.resolvers['myDefRes']
        response = self.create_realm('nopin', resolvers)
        assert '"value": true' in response, "Response: %r" % response

        resolvers = self.resolvers['myDefRes']
        response = self.create_realm('withpin', resolvers)
        assert '"value": true' in response, "Response: %r" % response

        return

    def create_tokens(self):
        """
        create the yubikey token and the remote token which points to it
        """

        # create local yubi token
        public_uid = 'ecebeeejedecebeg'
        y_serial = self.init_yubi_token(public_uid=public_uid)

        # set the yubi token realm
        params = {}
        params['serial'] = y_serial
        params['realms'] = 'nopin'
        response = self.make_admin_request('tokenrealm', params=params)
        assert '"value": 1' in response, response

        # get token info:
        # admin/show serial = serial and extract the otplen
        params = {}
        params['serial'] = y_serial
        response = self.make_admin_request('show', params=params)
        resp = json.loads(response.body)
        data = resp.get('result', {}).get('value', {}).get('data', [])
        assert len(data) > 0, response
        y_otplen = int(data[0].get("LinOtp.OtpLen", 0))
        assert y_otplen > 0, response

        # create remote token
        r_serial = self.init_remote_token(target_serial=y_serial,
                                          target_otplen=y_otplen)

        # set the yubi token realm
        params = {}
        params['serial'] = r_serial
        params['realms'] = 'withpin'
        response = self.make_admin_request('tokenrealm', params=params)
        assert '"value": 1' in response, response

        # get token info:
        # admin/show serial = serial and extract the otplen
        params = {}
        params['serial'] = r_serial
        response = self.make_admin_request('show', params=params)
        assert '"status": true' in response, response

        return (y_serial, r_serial)

    def create_local_tokens(self, serial):

        serial = "LSP%s" % serial

        # local token
        param_local_1 = {
                      "serial": serial,
                      "type": "spass",
                      "otpkey": "123456",
                      "otppin": "",
                      "user": "",
                      "pin": "pin",
                      }

        response = self.make_admin_request(action='init',
                                           params=param_local_1)
        assert '"value": true' in response, response
        return serial

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_unassigned_tokens(self):
        """
        RT2: unassigned remote token and target yubikey (check_s)
        """
        global HTTP_RESPONSE_FUNC

        (y_serial, r_serial) = self.create_tokens()

        # check otps on yubikey
        otp = self.yubi_valid_otps[0]

        params = {'serial': y_serial, 'pass': otp}
        response = self.make_validate_request(action='check_s', params=params)
        assert '"value": true' in response, response

        # check otps on remote
        otp = self.yubi_valid_otps[1]

        def check_func1(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content
        HTTP_RESPONSE_FUNC = check_func1

        params = {'serial': r_serial, 'pass': otp}
        response = self.make_validate_request(action='check_s', params=params)
        assert '"value": true' in response, response

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_assigned_tokens(self):
        """
        RT2: assigned remote token without pin and target yubikey
        """
        global HTTP_RESPONSE_FUNC

        (y_serial, r_serial) = self.create_tokens()

        params = {}
        params['serial'] = y_serial
        params['user'] = 'passthru_user1@nopin'
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response, response

        # check otps on yubikey
        otp = self.yubi_valid_otps[2]

        params = {'user': 'passthru_user1@nopin', 'pass': otp}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        # check otps on remote
        params = {}
        params['serial'] = r_serial
        params['user'] = 'passthru_user1@withpin'
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response, response

        otp = self.yubi_valid_otps[3]

        def check_func1(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content
        HTTP_RESPONSE_FUNC = check_func1

        params = {'user': 'passthru_user1@withpin', 'pass': otp}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_tokens_with_pin(self):
        """
        RT2: remote token with local pin and target yubikey
        """
        global HTTP_RESPONSE_FUNC

        (y_serial, r_serial) = self.create_tokens()

        params = {}
        params['serial'] = y_serial
        params['user'] = 'passthru_user1@nopin'
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response, response

        # check otps on yubikey
        otp = self.yubi_valid_otps[4]

        params = {'user': 'passthru_user1@nopin', 'pass': otp}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        # check otps on remote
        params = {}
        params['serial'] = r_serial
        params['user'] = 'passthru_user1@withpin'
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response, response

        params = {}
        params['serial'] = r_serial
        params['pin'] = 'local'
        response = self.make_admin_request('set', params)
        resp = json.loads(response.body)
        val = resp.get('result', {}).get('value', {})
        assert val['set pin'] == 1, response

        otp = self.yubi_valid_otps[5]
        passw = "local%s" % otp

        def check_func1(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content
        HTTP_RESPONSE_FUNC = check_func1

        params = {'user': 'passthru_user1@withpin', 'pass': passw}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_tokens_with_otppin_policy(self):
        """
        RT2: remote token with otppin policy and target yubikey
        """
        global HTTP_RESPONSE_FUNC

        self.create_pin_policies()

        (y_serial, r_serial) = self.create_tokens()

        params = {}
        params['serial'] = y_serial
        params['user'] = 'passthru_user1@nopin'
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response, response

        # check otps on yubikey
        otp = self.yubi_valid_otps[0]

        params = {'user': 'passthru_user1@nopin', 'pass': otp}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        # check otps on remote
        params = {}
        params['serial'] = r_serial
        params['user'] = 'passthru_user1@withpin'
        response = self.make_admin_request('assign', params)
        assert '"value": true' in response, response

        otp = self.yubi_valid_otps[1]
        passw = "geheim1%s" % otp

        def check_func1(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content
        HTTP_RESPONSE_FUNC = check_func1

        params = {'user': 'passthru_user1@withpin', 'pass': passw}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_tokens_with_autoassign(self):
        """
        RT2: remote token with otppin, autoassign policy and target yubikey
        """
        global HTTP_RESPONSE_FUNC

        self.create_pin_policies()
        self.create_autoassign_policy()

        (y_serial, r_serial) = self.create_tokens()

        # check otps on yubikey
        passw = "geheim1%s" % self.yubi_valid_otps[8]

        params = {'user': 'passthru_user1@nopin', 'pass': passw}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        params = {}
        params['serial'] = y_serial
        response = self.make_admin_request('show', params=params)
        resp = json.loads(response.body)
        data = resp.get('result', {}).get('value', {}).get('data', [])
        assert len(data) > 0, response
        username = data[0].get("User.username", '')
        assert username == 'passthru_user1', response

        # check otps on remote
        otp = self.yubi_valid_otps[9]
        passw = "geheim1%s" % otp

        def check_func1(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content
        HTTP_RESPONSE_FUNC = check_func1

        params = {'user': 'passthru_user1@withpin', 'pass': passw}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        params = {}
        params['serial'] = r_serial
        response = self.make_admin_request('show', params=params)
        resp = json.loads(response.body)
        data = resp.get('result', {}).get('value', {}).get('data', [])
        assert len(data) > 0, response
        username = data[0].get("User.username", '')
        assert username == 'passthru_user1', response

        return

    def test_00000_check_tokens_with_autoassign_forward(self):
        """
        RT2: remote token with otppin, autoassign forward policy and yubikey
        """
        self.skipTest("this test requires a real running linotp as it "
                      "triggers an outenrollment")

        self.create_pin_policies()
        self.create_autoassign_policy()
        self.create_autoassign_forward_policy()

        (y_serial, r_serial) = self.create_tokens()

        # check otps on remote
        otp = self.yubi_valid_otps[10]
        passw = "geheim1%s" % otp

        params = {'user': 'passthru_user1@withpin', 'pass': passw}
        response = self.make_validate_request(action='check', params=params)
        assert '"value": true' in response, response

        # get token info:
        # admin/show serial = serial and extract the owner
        params = {}
        params['serial'] = r_serial
        response = self.make_admin_request('show', params=params)
        resp = json.loads(response.body)
        data = resp.get('result', {}).get('value', {}).get('data', [])
        assert len(data) > 0, response
        username = data[0].get("User.username", '')
        assert username == 'passthru_user1', response

        params = {}
        params['serial'] = y_serial
        response = self.make_admin_request('show', params=params)
        resp = json.loads(response.body)
        data = resp.get('result', {}).get('value', {}).get('data', [])
        assert len(data) > 0, response
        username = data[0].get("User.username", '')
        assert username == 'passthru_user1', response

        return

#eof###########################################################################
