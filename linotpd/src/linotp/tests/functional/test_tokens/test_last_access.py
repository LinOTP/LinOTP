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


""" check if last access configuration does work """

import json
import freezegun

from datetime import datetime, timedelta

from linotp.tests import TestController
from linotp.lib.type_utils import DEFAULT_TIMEFORMAT


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

        params = {
            'serial': serial
        }
        response = self.make_admin_request('show', params)
        assert '"status": true' in response, response.body

        jresp = json.loads(response.body)
        token = jresp['result']['value']['data'][0]
        assert 'LinOtp.CreationDate' in token

        # get the time from the string
        created = token['LinOtp.CreationDate']
        created_date = datetime.strptime(created, DEFAULT_TIMEFORMAT)

        accessed = token['LinOtp.LastAuthMatch']
        assert not accessed

        # ------------------------------------------------------------------ --

        # now define a different time format "%Y/%m/%d %H:%M"

        time_fmt = "%Y/%m/%d %H:%M:%S"

        params = {
            'token.last_access': time_fmt
        }
        response = self.make_system_request('setConfig', params=params)
        assert 'token.last_access' in response, response.body

        frozen1 = datetime.now() + timedelta(seconds=3)

        with freezegun.freeze_time(frozen1):
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
            token = jresp['result']['value']['data'][0]
            assert 'LinOtp.LastAuthMatch' in token

            # get the time from the string
            invalid_access = token['LinOtp.LastAuthMatch']
            invalid_access_date = datetime.strptime(
                                            invalid_access, DEFAULT_TIMEFORMAT)

        frozen2 = frozen1 + timedelta(seconds=3)

        with freezegun.freeze_time(frozen2):

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
            token = jresp['result']['value']['data'][0]
            assert 'LinOtp.LastAuthSuccess' in token

            # verify that we can parse the iso format
            valid_access = invalid_access = token['LinOtp.LastAuthSuccess']
            valid_access_date = datetime.strptime(
                                    valid_access, DEFAULT_TIMEFORMAT)

        assert created_date < invalid_access_date < valid_access_date

        self.delete_all_token()
        return
