# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2019 KeyIdentity GmbH
#   Copyright (C) 2019 -      netgo software GmbH
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
#   E-mail: info@linotp.de
#   Contact: www.linotp.org
#   Support: www.linotp.de

"""
SQL Resolver unit test - test passwords formats
"""

import unittest

from passlib.hash import atlassian_pbkdf2_sha1

from linotp.useridresolver.SQLIdResolver import _check_hash_type
from linotp.useridresolver.SQLIdResolver import check_php_password
from linotp.useridresolver.SQLIdResolver import check_bcypt_password


class TestSQLResolver_Password(unittest.TestCase):

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

    def test_bcypt_password(self):
        """ check the bcypt password verification method """

        password = 'password'
        password_hash = ('$2a$12$NT0I31Sa7ihGEWpka9ASYrEFk'
                         'huTNeBQ2xfZskIiiJeyFXhRgS.Sy')
        res = check_bcypt_password(password, password_hash)
        assert res == True

        wrong_password_hash = password_hash.replace('h','t')

        res = check_bcypt_password(password, wrong_password_hash)
        assert res == False

        wrong_password = password + '!'

        res = check_bcypt_password(wrong_password, password_hash)
        assert res == False

    def test_php_passwords(self):
        """ check the php password verification method """

        password = 'password'
        password_hash ='$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'

        res = check_php_password(password, password_hash)
        assert res == True

        wrong_password_hash = password_hash.replace('U','Z')

        res = check_php_password(password, wrong_password_hash)
        assert res == False

        wrong_password = password + '!'

        res = check_php_password(wrong_password, password_hash)
        assert res == False
