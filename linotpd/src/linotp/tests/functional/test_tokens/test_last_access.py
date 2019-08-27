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


""" check if last access configuration does work """

import json
from datetime import datetime

from linotp.tests import TestController


class TestLastAccess(TestController):
    '''
    '''

    def test_last_access_timeformat(self):
        """ check that last_access does work with time format expressions """

        serial = 'last_access_token'

        params = {
            'serial': serial,
            'type': 'pw',
            'otpkey': 'geheim',
            'pin': '123!'
        }

        response = self.make_admin_request('init', params=params)
        assert '<img' in response, response.body

        # ------------------------------------------------------------------ --

        # now define a different time format "%Y/%m/%d %H:%M"

        time_fmt = "%Y/%m/%d %H:%M:%S:%f"

        params = {
            'token.last_access': time_fmt
        }
        response = self.make_system_request('setConfig', params=params)
        assert 'token.last_access' in response, response.body

        params = {
            'serial': serial,
            'pass': '123!geheimXXX'
        }
        response = self.make_validate_request('check_s', params=params)
        assert '"status": true' in response, response.body
        assert '"value": false' in response, response.body

        params = {
            'serial': serial
        }
        response = self.make_admin_request('show', params)
        assert '"status": true' in response, response.body

        jresp = json.loads(response.body)
        t_info = jresp['result']['value']['data'][0]['LinOtp.TokenInfo']
        token_info = json.loads(t_info)
        assert 'last_access' in token_info

        # verify that we can parse the iso format
        invalid_access = token_info['last_access']
        _invalid_access_date = datetime.strptime(invalid_access, time_fmt)

        params = {
            'serial': serial,
            'pass': '123!geheim'
        }
        response = self.make_validate_request('check_s', params=params)
        assert '"status": true' in response, response.body
        assert '"value": true' in response, response.body

        params = {
            'serial': serial
        }
        response = self.make_admin_request('show', params)
        assert '"status": true' in response, response.body

        jresp = json.loads(response.body)
        t_info = jresp['result']['value']['data'][0]['LinOtp.TokenInfo']
        token_info = json.loads(t_info)
        assert 'last_access' in token_info

        # verify that we can parse the iso format
        valid_access = token_info['last_access']
        _valid_access_date = datetime.strptime(valid_access, time_fmt)

        assert invalid_access != valid_access

        self.delete_all_token()
        return
