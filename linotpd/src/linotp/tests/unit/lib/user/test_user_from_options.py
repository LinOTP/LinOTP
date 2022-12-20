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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

import json
import unittest
from mock import patch

from linotp.lib.user import get_user_from_options
from linotp.lib.user import User


class TestGetUserFromOptions(unittest.TestCase):


    @patch('linotp.lib.user.getUserFromParam')
    def test_run_test_vector(self,
                         mock_getUserFromParam
                         ):
        """
        test a set of options dict values with fallback user and fallback realm
        """

        test_sets = [
                    # 1. test simple login name in options
                    {'options_dict': {'user': 'amigo'},
                      'user_from_param' : User('amigo', 'defRealm'),
                      'result': {'login': 'amigo', 'realm': 'defRealm'}},

                     # 2. test login and realn in options
                     {'options_dict': {'user': 'amigo', 'realm': 'mexico'},
                      'user_from_param' : User('amigo', 'mexico'),
                      'result': {'login': 'amigo', 'realm': 'mexico'}},

                     # 3. test user object in options
                     {'options_dict': {'user': User('amigo', 'mexico')},
                      'user_from_param' : User('amigo', 'mexico'),
                      'result': {'login': 'amigo', 'realm': 'mexico'}},

                     # 4. test no login and no realn in options
                     {'options_dict': {},
                      'user_from_param' : User('', ''),
                      'result': {'login': 'token_owner', 'realm': 'norealm'}},

                     # 5. test no login and realn in options
                     {'options_dict': { 'user': '', 'realm': 'norway'},
                      'user_from_param' : User('', 'norway'),
                      'result': {'login': 'token_owner', 'realm': 'norealm'}},
        ]  # eof test sets


        for run in test_sets:

            options_dict = run['options_dict']
            mock_getUserFromParam.return_value = run['user_from_param']

            result = run['result']

            login, realm = get_user_from_options(
                                options_dict=options_dict,
                                fallback_user=User('token_owner', 'norealm'),
                                fallback_realm='norealm')

            assert (login == result['login'] and realm == result['realm'],
                        "failed on run %r:%r:%r" % (login, realm, run))

        return

    @patch('linotp.lib.user.getUserFromParam')
    def test_run_test_vector_without_fallback_user(self,
                         mock_getUserFromParam
                         ):
        """
        test a set of options dict values without fallback user and fallback realm
        """

        test_sets = [
                    # 1. test simple login name in options
                    {'options_dict': {'user': 'amigo'},
                      'user_from_param' : User('amigo', 'defRealm'),
                      'result': {'login': 'amigo', 'realm': 'defRealm'}},

                     # 2. test login and realn in options
                     {'options_dict': {'user': 'amigo', 'realm': 'mexico'},
                      'user_from_param' : User('amigo', 'mexico'),
                      'result': {'login': 'amigo', 'realm': 'mexico'}},

                     # 3. test user object in options
                     {'options_dict': {'user': User('amigo', 'mexico')},
                      'user_from_param' : User('amigo', 'mexico'),
                      'result': {'login': 'amigo', 'realm': 'mexico'}},

                     # 4. test no login and no realn in options
                     {'options_dict': {},
                      'user_from_param' : User('', ''),
                      'result': {'login': '', 'realm': 'norealm'}},

                     # 5. test no login and realn in options
                     {'options_dict': { 'user': '', 'realm': 'norway'},
                      'user_from_param' : User('', 'norway'),
                      'result': {'login': '', 'realm': 'norealm'}},

        ]  # eof test sets


        for run in test_sets:

            options_dict = run['options_dict']
            mock_getUserFromParam.return_value = run['user_from_param']

            result = run['result']

            login, realm = get_user_from_options(
                                options_dict=options_dict,
                                fallback_user=None,
                                fallback_realm='norealm')

            assert (login == result['login'] and realm == result['realm'],
                        "failed on run %r:%r:%r" % (login, realm, run))

        return

# eof #
