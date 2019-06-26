# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#   This file is part of LinOTP userid resolvers.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU Affero General Public
#   License, version 3, as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the
#              GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#   E-mail: linotp@keyidentity.com
#   Contact: www.linotp.org
#   Support: www.keyidentity.com

"""
SQL Resolver unit test - test atlasian passwords
"""

import unittest

from passlib.hash import atlassian_pbkdf2_sha1

from linotp.useridresolver.SQLIdResolver import _check_hash_type


class TestSQLResolver_PKCS5S2_Password(unittest.TestCase):

    def test_pbkdf2_password(self):

        brahms_hashed_pw = ('{PKCS5S2}TGF1K1olIoY5a4HHy89R+LcT8E/V5P+'
                            'u92L0ClePbhzqWikJUGmS0lyHSibsj4th')

        brahms_pw = 'brahms123'

        res = atlassian_pbkdf2_sha1.verify(brahms_pw, brahms_hashed_pw)
        assert res

        hash_type, _sep, hash_value = brahms_hashed_pw.partition('}')
        hash_type = hash_type.strip('{')

        res =_check_hash_type(brahms_pw, hash_type, hash_value)
        assert res

        wrong_hash_type = 'OKCS5S2'
        res =_check_hash_type(brahms_pw, wrong_hash_type, hash_value)
        assert res == False

        wrong_hash_value = hash_value.replace('+','-')
        res =_check_hash_type(brahms_pw, hash_type, wrong_hash_value)
        assert res == False

        wrong_hash_value = hash_value.replace('G','Q')
        res =_check_hash_type(brahms_pw, hash_type, wrong_hash_value)
        assert res == False