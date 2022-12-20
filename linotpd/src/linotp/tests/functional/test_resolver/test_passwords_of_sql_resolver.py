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

"""
sql resolver tests
"""

import logging
import json

from passlib.hash import atlassian_pbkdf2_sha1
from passlib.hash import bcrypt as passlib_bcrypt
from passlib.hash import phpass as passlib_phpass


from .sql_test_controller import SQLTestController

log = logging.getLogger(__name__)


class SQLResolverPasswordTest(SQLTestController):

    def setUp(self):
        """ create an sql user table some users and the sql resolver """

        SQLTestController.setUp(self)
        self.setUpSQL()

        return

    def tearDown(self):
        """ drop the users and the user table """

        self.dropUsers()
        self.delete_all_token()

        return SQLTestController.tearDown(self)


    def define_otp_pin_policy(self, otppin='password'):
        """
        create the policy to check for password instead of pin
        """

        params = {
            'name': 'otppin_poilcy',
            'action': 'otppin=' + otppin,
            'scope': 'authentication',
            'user': '*',
            'realm': '*',
            }

        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('false' not in response.body)


    def test_sqlresolver_passwords(self):
        """
        test that we can use pbkdf2 and bcrypt passwords with an sql resolver
        """

        users = {}

        # ------------------------------------------------------------------ --

        # create the User schema

        self.createUserTable()

        # ------------------------------------------------------------------ --

        # add users

        bach_password = "bach123"
        bach_password_hash = ('{PKCS5S2}ZYIjvFLd99ldgx5b7sqOlDCKNt31'
                              'UBX9HQKxTZwU50WfuZlWTNG5qBsCsFUMWwxC')

        users['bach'] = {
            'login': 'bach',
            'uid': '21.3.1685',
            'telephonenumber': '',
            'mobile': bach_password,
            'surname': 'Bach',
            'givenname': 'Johann Sebastian',
            'password': bach_password_hash,
            'mail': 'j.s@bach.de'
        }

        assert atlassian_pbkdf2_sha1.verify(bach_password, bach_password_hash)
        self.addUser(**users['bach'])

        # ------------------------------------------------------------------ --

        chopin_password = "chopin123"
        chopin_password_hash = atlassian_pbkdf2_sha1.hash(chopin_password)

        users['chopin'] = {
            'login': 'chopin',
            'uid': '22.10.1849',
            'telephonenumber': '',
            'mobile': chopin_password,
            'surname': 'Chopin',
            'givenname': 'Fryderyk Franciszek',
            'password': chopin_password_hash,
            'mail': 'f.f@chopin.de'
        }

        assert atlassian_pbkdf2_sha1.verify(
            chopin_password, chopin_password_hash)
        self.addUser(**users['chopin'])

        # ------------------------------------------------------------------ --

        brahms_password = 'password'
        brahms_password_hash = ('$2a$12$NT0I31Sa7ihGEWpka9ASYrEFk'
                                'huTNeBQ2xfZskIiiJeyFXhRgS.Sy')

        users['brahms'] = {
            'login': 'brahms',
            'uid': '7.5.1833',
            'telephonenumber': '',
            'mobile': brahms_password,
            'surname': 'Brahms',
            'givenname': 'Johannes',
            'password': brahms_password_hash,
            'mail': 'johannes@brahms.de'
        }

        assert passlib_bcrypt.verify(brahms_password, brahms_password_hash)

        self.addUser(**users['brahms'])

        # ------------------------------------------------------------------ --

        mozart_password = 'mozart123'
        mozart_password_hash = passlib_bcrypt.hash(mozart_password)

        users['mozart'] = {
            'login': 'mozart',
            'uid': '27.1.1756',
            'telephonenumber': '',
            'mobile': mozart_password,
            'surname': 'Mozart',
            'givenname': 'Wolfgang Amadeus',
            'password': mozart_password_hash,
            'mail': 'wolfgang.amadeus@mozart.de'
        }

        assert passlib_bcrypt.verify(mozart_password, mozart_password_hash)

        self.addUser(**users['mozart'])

        # ------------------------------------------------------------------ --

        schubert_password = 'password'
        schubert_password_hash = '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'

        users['schubert'] = {
            'login': 'schubert',
            'uid': '31.1.1797',
            'telephonenumber': '',
            'mobile': schubert_password,
            'surname': 'Schubert',
            'givenname': 'Franz Peter',
            'password': schubert_password_hash,
            'mail': 'franz.peter@schubert.de'
        }

        assert passlib_phpass.verify(schubert_password, schubert_password_hash)

        self.addUser(**users['schubert'])

        # ------------------------------------------------------------------ --

        mendelssohn_password = 'mendelssohn123'
        mendelssohn_password_hash = passlib_phpass.hash(mendelssohn_password)

        users['mendelssohn'] = {
            'login': 'mendelssohn',
            'uid': '31.2.1809',
            'telephonenumber': '',
            'mobile': mendelssohn_password,
            'surname': 'Mendelssohn',
            'givenname': 'Jakob Ludwig',
            'password': mendelssohn_password_hash,
            'mail': 'jakob.ludwig@mendelssohn.de'
        }

        assert passlib_phpass.verify(
            mendelssohn_password, mendelssohn_password_hash)

        self.addUser(**users['mendelssohn'])

        # ------------------------------------------------------------- --

        # define resolver and realm

        realm = 'sqlRealm'

        self.addSqlResolver('my_sql_users')
        self.addSqlRealm(realm, 'my_sql_users', defaultRealm=True)

        # ------------------------------------------------------------- --

        # run the pbkdf2 atlasian test with user bach

        user = users['bach']['login']
        password = users['bach']['mobile']

        self.run_password_check(user, password, realm=realm)

        # run the pbkdf2 atlasian test with user chopin

        user = users['chopin']['login']
        password = users['chopin']['mobile']

        self.run_password_check(user, password, realm=realm)


        # run the bcrypt test with user brahms

        user = users['brahms']['login']
        password = users['brahms']['mobile']

        self.run_password_check(user, password, realm=realm)

        # run the bcrypt test with user mozart

        user = users['mozart']['login']
        password = users['mozart']['mobile']

        self.run_password_check(user, password, realm=realm)

        # run the php test with user schubert

        user = users['schubert']['login']
        password = users['schubert']['mobile']

        self.run_password_check(user, password, realm=realm)

        # run the php test with user mendelssohn

        user = users['mendelssohn']['login']
        password = users['mendelssohn']['mobile']

        self.run_password_check(user, password, realm=realm)

        return

    def run_password_check(self, user, password, realm):

        self.define_otp_pin_policy('pin')

        # ------------------------------------------------------------------ --

        # create token for user

        pin = 'mypin!'
        secret = 'mein_geheimnis'
        serial = 'pw_' + user

        params = {
            'type': 'pw',
            'otpkey': secret,
            'user': user,
            'realm': realm,
            'serial': serial,
            'pin': pin
        }

        response = self.make_admin_request('init', params=params)
        self.assertTrue('false' not in response.body, response)

        # ------------------------------------------------------------------ --

        # run a wrong login, so that the token failcount increments

        params = {
            'user': user,
            'pass': pin + '1' + secret
            }

        response = self.make_validate_request('check', params=params)
        self.assertTrue('"value": false' in response)

        # ------------------------------------------------------------------ --

        # verify that the token count is incremented to 1

        params = {
            'serial': serial
            }

        response = self.make_admin_request('show', params=params)
        jresp = json.loads(response.body)
        token_info = jresp.get(
            'result', {}).get(
                'value', {}).get(
                    'data',[{}])[0]
        self.assertTrue(token_info.get( "LinOtp.FailCount", -1) == 1)

        # ------------------------------------------------------------------ --

        # now login to the selfservice and run the token reset

        # run a wrong login, so that the token failcount increments

        params = {
            'user': user,
            'pass': pin + secret
            }

        response = self.make_validate_request('check', params=params)
        self.assertTrue('"value": true' in response)


        # ------------------------------------------------------------------ --

        # create the policy to check for password instead of pin

        self.define_otp_pin_policy('password')

        # ------------------------------------------------------------------ --

        # verify that correct password works

        params = {
            'user': user,
            'pass': password + secret
            }

        response = self.make_validate_request('check', params=params)
        self.assertTrue('"value": true' in response)

        # verify that wrong password works

        params = {
            'user': user,
            'pass': password + '1' + secret
            }

        response = self.make_validate_request('check', params=params)
        self.assertTrue('"value": false' in response)

        return



# eof
