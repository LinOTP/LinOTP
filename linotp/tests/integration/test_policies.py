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
Test policies
 - test_otppin_3 (TestRail C1910)
"""

import binascii
import pytest

from linotp_selenium_helper import TestCase, Policy
from linotp_selenium_helper.token_import import TokenImportAladdin
from linotp_selenium_helper.validate import Validate

from linotp.lib.HMAC import HmacOtp

import integration_data as data


class TestPolicies(TestCase):
    """Test Policies"""

    # GUI attributes
    token_view = None
    user_view = None

    # Other testing data
    seed_oath137332 = None
    serial_oath137332 = None

    ldap_resolver = None
    sql_resolver = None

    two_resolvers_realm_name = None

    @pytest.fixture(autouse=True)
    def setUp(self):
        """ Some test set up steps """

        # Initialize GUI attributes
        self.token_view = self.manage_ui.token_view
        self.user_view = self.manage_ui.user_view

        # Delete from previous tests:
        # - resolvers
        # - realms
        # - policies
        # - tokens

        self.reset_resolvers_and_realms()
        self.manage_ui.policy_view.clear_policies_via_api()
        self.token_view.clear_tokens_via_api()

        # Create LDAP UserIdResolver
        ldap_data = data.musicians_ldap_resolver
        self.ldap_resolver = self.useridresolver_manager.create_resolver(
            ldap_data)

        # Create SQL UserIdResolver
        sql_data = data.sql_resolver

        self.sql_resolver = self.useridresolver_manager.create_resolver(
            sql_data)
        self.useridresolver_manager.close()

        # Create realms
        self.two_resolvers_realm_name = "two_resolvers_realm"
        self.realm_manager.create(self.two_resolvers_realm_name, [self.ldap_resolver,
                                                                  self.sql_resolver])
        self.realm_manager.close()

        # Set seed of HMAC token
        self.seed_oath137332 = "ff06df50017d3b981cfbc4ec4d374040164d8d19"
        self.serial_oath137332 = "oath137332"

        # Import some test tokens
        self.import_tokens()

    def test_otppin_3(self):
        """
        Test policy otppin=3 (ignore_pin) : TestRail C1910

        First we do some authentications with user a with
        otppin=3.

        Then we change the policy, that only users from
        a specific resolver (user B) get through with otppin=3.
        """

        # Define user A
        user_a = "bach"
        user_a_pw = "Test123!"
        user_a_realm = self.two_resolvers_realm_name
        user_a_token_pin = "1234"

        # Define user B
        user_b = "kay"
        user_b_pw = "test123!"
        user_b_realm = self.two_resolvers_realm_name
        user_b_token_pin = ""
        user_b_token_key = "3132333435363738393031323334353637383930"

        # Unhexlify for hotp.generate method
        user_b_token_seed_bin = binascii.unhexlify(user_b_token_key)

        # Create Token
        self.user_view.select_user(user_b)
        self.manage_ui.token_enroll.create_hotp_token(
                  pin=user_b_token_pin,
                  hmac_key=user_b_token_key)

        ###############################
        ##
        # First some tests with user A
        ##
        ###############################

        # Create policy
        Policy(self.manage_ui, "otppin3", "authentication",
               "otppin=3",
               "*",
               "*")  # user = "*"

        # Create event based HMAC token
        # Tokens were imported by self.import_tokens()
        self.user_view.select_realm(user_a_realm)
        self.user_view.select_user(user_a)

        # Unhexlify for hotp.generate method
        seed_oath137332_bin = binascii.unhexlify(self.seed_oath137332)

        # Assign token to user
        # Set a pin
        self.token_view.assign_token(self.serial_oath137332,
                                     user_a_token_pin)

        # authentication tests
        # - PIN+OTP -> successfully
        # - PW+OTP -> successfully
        # - nonsense+OTP -> successfully
        # - OTP -> successfully
        # - wront OTP -> fails

        hotp_a = HmacOtp()

        # PIN+OTP -> success
        otp = user_a_token_pin + \
            hotp_a.generate(counter=0,
                            key=seed_oath137332_bin)

        access_granted, _ = self.validate.validate(user=user_a + "@" +
                                                   user_a_realm, password=otp)
        assert access_granted, "OTPPIN=3, PIN+OTP: " + otp + " for user " + \
                        user_a + "@" + user_a_realm + " returned False"

        # PW+OTP -> success
        otp = user_a_pw + \
            hotp_a.generate(counter=1,
                            key=seed_oath137332_bin)

        access_granted, _ = self.validate.validate(user=user_a + "@" +
                                                   user_a_realm, password=otp)
        assert access_granted, "OTPPIN=3, PW+OTP: " + otp + " for user " + \
                        user_a + "@" + user_a_realm + " returned False"

        # nonsense+OTP -> success
        otp = "nonsense" + \
            hotp_a.generate(counter=2,
                            key=seed_oath137332_bin)

        access_granted, _ = self.validate.validate(user=user_a + "@" +
                                                   user_a_realm, password=otp)
        assert access_granted, "OTPPIN=3, nonsense+OTP: " + otp + " for user " + \
                        user_a + "@" + user_a_realm + " returned False"

        # OTP -> success
        otp = hotp_a.generate(counter=3,
                              key=seed_oath137332_bin)

        access_granted, _ = self.validate.validate(user=user_a + "@" +
                                                   user_a_realm, password=otp)
        assert access_granted, "OTPPIN=3, OTP: " + otp + " for user " + \
                        user_a + "@" + user_a_realm + " returned False"

        # wrong OTP -> fails
        otp = "111111"

        access_denied, _ = self.validate.validate(user=user_a + "@" +
                                                  user_a_realm, password=otp)
        assert not access_denied, "OTPPIN=3, wrong OTP: " + otp + " for user " + \
                         user_a + "@" + user_a_realm + " returned True"

        ###########################
        #
        # Bring user B into game
        #
        # change policy
        #    user = resolverB:
        #
        # So the ignore_pin should
        # should only affect users
        # in resolverB
        #
        ###########################

        # Change policy
        Policy(self.manage_ui, "otppin3", "authentication",
               "otppin=3",
               "*",  # realm
               data.sql_resolver["name"] + ":")  # pick specific resolver

        hotp_b = HmacOtp()

        # PIN+OTP -> success
        otp = user_b_token_pin + \
            hotp_b.generate(counter=0,
                            key=user_b_token_seed_bin)

        access_granted, _ = self.validate.validate(user=user_b + "@" +
                                                   user_b_realm, password=otp)
        assert access_granted, "OTPPIN=3, PIN+OTP: " + otp + " for user " + \
                        user_b + "@" + user_b_realm + " returned False"

        # PW+OTP -> success
        otp = user_b_pw + \
            hotp_b.generate(counter=1,
                            key=user_b_token_seed_bin)

        access_granted, _ = self.validate.validate(user=user_b + "@" +
                                                   user_b_realm, password=otp)
        assert access_granted, "OTPPIN=3, PW+OTP: " + otp + " for user " + \
                        user_b + "@" + user_b_realm + " returned False"

        # OTP -> success
        otp = hotp_b.generate(counter=2,
                              key=user_b_token_seed_bin)

        access_granted, _ = self.validate.validate(user=user_b + "@" +
                                                   user_b_realm, password=otp)
        assert access_granted, "OTPPIN=3, OTP: " + otp + " for user " + \
                        user_b + "@" + user_b_realm + " returned False"

        # wrong OTP -> fails
        otp = "111111"

        access_denied, _ = self.validate.validate(user=user_b + "@" +
                                                  user_b_realm, password=otp)
        assert not access_denied, "OTPPIN=3, wrong OTP: " + otp + " for user " + \
                         user_b + "@" + user_b_realm + " returned False"

        # Back to user A and try to authenticate
        # with changed policy!

        # OTP -> fails
        otp = hotp_a.generate(counter=4,
                              inc_counter=False,
                              key=seed_oath137332_bin)

        access_denied, _ = self.validate.validate(user=user_a + "@" +
                                                  user_a_realm, password=otp)
        assert not access_denied, "OTPPIN=3, OTP: " + otp + " for user " + \
                         user_a + "@" + user_a_realm + " returned True"

        # PIN+OTP -> success
        otp = user_a_token_pin + \
            hotp_a.generate(counter=4,
                            key=seed_oath137332_bin)

        access_granted, _ = self.validate.validate(user=user_a + "@" +
                                                   user_a_realm, password=otp)
        assert access_granted, "OTPPIN=3, PIN+OTP: " + otp + " for user " + \
                        user_a + "@" + user_a_realm + " returned False"

    def import_tokens(self):
        """ Import some tokens """

        file_content = """<Tokens>
    <Token serial="00040008CFA5">
    <CaseModel>5</CaseModel>
    <Model>101</Model>
    <ProductionDate>02/19/2009</ProductionDate>
    <ProductName>Safeword Alpine</ProductName>
    <Applications>
    <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
    <Seed>123412354</Seed>
    <MovingFactor>1</MovingFactor>
    </Application>
    </Applications>
    </Token>
    <Token serial="00040008CFA52">
    <CaseModel>5</CaseModel>
    <Model>101</Model>
    <ProductionDate>02/19/2009</ProductionDate>
    <ProductName>Safeword Alpine</ProductName>
    <Applications>
    <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
    <Seed>123456</Seed>
    <MovingFactor>1</MovingFactor>
    </Application>
    </Applications>
    </Token>
    <Token serial="oath137332">
    <CaseModel>5</CaseModel>
    <Model>101</Model>
    <ProductionDate>02/19/2009</ProductionDate>
    <ProductName>Safeword Alpine</ProductName>
    <Applications>
    <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb1}">
    <Seed>""" + self.seed_oath137332 + """</Seed>
    <MovingFactor>1</MovingFactor>
    </Application>
    </Applications>
    </Token>
    <Token serial="oath12482B">
    <CaseModel>5</CaseModel>
    <Model>101</Model>
    <ProductionDate>02/19/2009</ProductionDate>
    <ProductName>Safeword Alpine</ProductName>
    <Applications>
    <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb2}">
    <Seed>6ec1d0e9915a2bebf84745b318e39e481249c1eb</Seed>
    <MovingFactor>1</MovingFactor>
    </Application>
    </Applications>
    </Token>
    </Tokens>"""

        token_import_aladdin = TokenImportAladdin(self.manage_ui)
        token_import_aladdin.do_import(file_content)
