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

import json
import logging

from datetime import datetime
from datetime import timedelta
from pylons import config
from sqlalchemy import engine_from_config
from sqlalchemy.orm import scoped_session, sessionmaker

from linotp.model import Reporting

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestReportingController(TestController):

    def setUp(self):
        self.delete_all_policies()
        self.delete_reports()
        self.delete_all_realms()
        self.delete_all_resolvers()
        super(TestReportingController, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        return

    def tearDown(self):
        self.delete_all_token()
        super(TestReportingController, self).tearDown()

# ------------------------------------------------------------------------------
    # Helper functions

    def create_token(self, serial="1234567", realm=None, user=None,
                     active=True):
        """
        create an HMAC Token with given parameters

        :param serial:  serial number, must be unique per token and test
        :param realm:   optional: set token realm
        :param user:    optional: assign token to user
        :param active:  optional: if this is False, token will be disabled
        :return: serial of new token
        """
        parameters = {
            'serial': serial,
            'otpkey': 'AD8EABE235FC57C815B26CEF37090755',
            'description': 'TestToken' + serial,
        }
        if realm:
            parameters['realm'] = realm
        if user:
            parameters['user'] = user

        response = self.make_authenticated_request(controller='admin',
                                                   action='init',
                                                   params=parameters)
        self.assertTrue('"value": true' in response, response)
        if active is False:
            response = self.make_authenticated_request(controller='admin',
                                                       action='disable',
                                                       params={
                                                           'serial': serial})

            self.assertTrue('"value": 1' in response, response)
        return serial

    def delete_reports(self):
        """
        empty table Reporting
        """
        response = self.make_authenticated_request(controller='reporting',
                                                   action='delete_all',
                                                   params={'realms': '*',
                                                           'status': '*'})
        resp = json.loads(response.body)
        values = resp.get('result')
        self.assertEqual(values.get('status'), True, response)

# ------------------------------------------------------------------------------
    # Tests

    def test_init_token(self):
        # set policy:
        policy_params = {'name': 'test_init_token',
                         'scope': 'reporting',
                         'action': 'token_total',
                         'user': '*',
                         'realm': 'mydefrealm,mymixrealm',
                         }
        self.create_policy(policy_params)

        self.create_token(serial='0001', realm='mymixrealm', user='hans')

        Session=None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False, autoflush=True))
            Session.configure(bind=engine)
            # check if new entry was created in reporting table
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 1, table_content)
        finally:
            if Session:
                Session.close()

    def test_reporting_status_active(self):
        # set policy:
        policy_params = {'name': 'test_active',
                         'scope': 'reporting',
                         'action': 'token_total, token_status=active',
                         'user': '*',
                         'realm': 'mydefrealm,mymixrealm',
                         }
        self.create_policy(policy_params)

        self.create_token(serial='0011', realm='mymixrealm', user='hans')
        self.create_token(serial='0012', user='hans')
        self.create_token(serial='0013', realm='mymixrealm', user='hans',
                          active=False)
        self.create_token(serial='0014', realm='mydefrealm', user='hans')
        self.create_token(serial='0015', realm='mymixrealm', user='lorca')
        self.create_token(serial='0016', realm='myotherrealm')

        Session=None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False, autoflush=True))
            Session.configure(bind=engine)
            # check if new entry was created in reporting table
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 12, table_content)

            parameters = {'user': 'hans'}
            self.make_authenticated_request(controller='admin',
                                                       action='disable',
                                                       params=parameters)
            # refresh Session
            Session.commit()
            table_content = Session.query(Reporting).filter(
                Reporting.parameter == 'active')
            self.assertEqual(table_content.count(), 7, table_content)
        finally:
            if Session:
                Session.close()

    def test_multi_actions_in_reporting_policy(self):
        # set policy:
        policy_params = {
            'name': 'test_multi_actions',
            'scope': 'reporting',
            'action': 'token_total,token_status=active,token_status=inactive',
            'user': '*',
            'realm': 'mydefrealm,mymixrealm',
        }

        self.create_policy(policy_params)

        self.create_token(serial='0021', realm='mymixrealm', user='hans')

        Session=None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False, autoflush=True))
            Session.configure(bind=engine)
            # check if new entry was created in reporting table
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 3, table_content)
        finally:
            if Session:
                Session.close()

    def test_del_before(self):
        """
        test delete rows from reporting table which are older than date
        """
        Session=None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False, autoflush=True))
            Session.configure(bind=engine)

            # create table entries
            today = datetime.now()
            yesterday = today - timedelta(days=1)
            two_days_ago = today - timedelta(days=2)

            # create old reports:
            report_2 = Reporting(timestamp=two_days_ago, event='token_init',
                                 realm='mydefrealm', parameter='active', count=1)
            report_1 = Reporting(timestamp=yesterday, event='token_init',
                                 realm='mydefrealm', parameter='active', count=2)
            report_0 = Reporting(event='token_init',
                                 realm='mydefrealm', parameter='active', count=3)
            Session.add(report_0)
            Session.add(report_1)
            Session.add(report_2)
            Session.commit()

            # check if reports are in database
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 3, table_content)

            # delete reports
            yest = yesterday.strftime("%Y-%m-%d")
            parameter = {'date': yest, 'realms': '*', 'status': 'active'}
            response = self.make_authenticated_request(controller='reporting',
                                                       action='delete_before',
                                                       params=parameter)
            resp = json.loads(response.body)
            values = resp.get('result')
            self.assertEqual(values.get('status'), True, response)
            self.assertEqual(values.get('value'), 1, response)
        finally:
            if Session:
                Session.close()

    def test_delete_all_reports(self):
        Session=None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False, autoflush=True))
            Session.configure(bind=engine)

            # check if table is empty
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 0, table_content)

            # create table entries
            today = datetime.now()
            yesterday = today - timedelta(days=1)

            report_1 = Reporting(timestamp=yesterday, event='token_init',
                                 realm='mydefrealm', parameter='active', count=1)
            report_2 = Reporting(event='token_init',
                                 realm='mydefrealm', parameter='active', count=2)
            Session.add(report_1)
            Session.add(report_2)
            Session.commit()

            # check if reports are in database
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 2, table_content)

            # delete reports
            response = self.make_authenticated_request(controller='reporting',
                                                       action='delete_all',
                                                       params={'realm': '*',
                                                               'status': 'active'})
            resp = json.loads(response.body)
            values = resp.get('result')
            self.assertEqual(values.get('status'), True, response)
            self.assertEqual(values.get('value'), 2, response)

            # refresh Session
            Session.commit()
            # check if database table is empty
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 0, table_content)
        finally:
            if Session:
                Session.close()

    def test_selfservice(self):
        # set policies:
        policy_params = {'name': 'test_init_token_1',
                         'scope': 'reporting',
                         'action': 'token_total',
                         'user': '*',
                         'realm': 'mydefrealm,mymixrealm',
                         }
        self.create_policy(policy_params)

        response = self.make_authenticated_request(
            controller='system', action='setPolicy',
            params={'name': 'self01',
                    'realm': 'mydefrealm',
                    'scope': 'selfservice',
                    'action': 'enrollHMAC',
                    'selftest_admin': 'superadmin'})
        resp = json.loads(response.body)
        values = resp.get('result')
        self.assertEqual(values.get('status'), True, response)
        self.assertEqual(values.get('value').get(
            'setPolicy self01').get('action'), True, response)

        # do userservice request
        self.make_userservice_request(
            action='enroll',
            auth_user=('passthru_user1@myDefRealm', 'geheim1'),
            params={'serial': 'token01',
                    'type': 'hmac',
                    'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                    })
        Session=None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False, autoflush=True))
            Session.configure(bind=engine)
            # check if new entry was created in reporting table
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 1, table_content)
        finally:
            if Session:
                Session.close()

    def test_reporting_maximum(self):
        """
        test reporting/maximum
        """
        # set policy:
        policy_params = {'name': 'test_maximum',
                         'scope': 'reporting',
                         'action': 'token_total, token_status=active',
                         'user': '*',
                         'realm': 'mydefrealm,mymixrealm',
                         }
        self.create_policy(policy_params)

        self.create_token(serial='0031', realm='mydefrealm', user='hans')
        self.create_token(serial='0032', user='hans')
        self.create_token(serial='0033', realm='mymixrealm', user='hans',
                          active=False)
        self.create_token(serial='0034', realm='mydefrealm', user='hans')
        self.create_token(serial='0035', realm='mydefrealm', user='lorca')
        self.create_token(serial='0036', realm='myotherrealm')

        parameters = {'user': 'hans'}
        self.make_authenticated_request(controller='admin',
                                        action='remove', params=parameters)
        response = self.make_authenticated_request(
            controller='reporting',
            action='maximum',
            params={'realms': 'mydefrealm, mymixrealm'})

        resp = json.loads(response.body)
        values = resp.get('result')
        self.assertEqual(values.get('status'), True, response)
        value = values.get('value')
        self.assertEqual(value.get('mydefrealm').get('total'), 4, response)
        self.assertEqual(value.get('mymixrealm').get('total'), 1, response)

    def test_reporting_access_policy(self):
        policy_params = {'name': 'test_report_policy',
                         'scope': 'reporting.access',
                         'action': 'maximum',
                         'user': 'Hans',
                         'realm': '*',
                         }
        self.create_policy(policy_params)
        response = self.make_authenticated_request(controller='reporting',
                                                  action='maximum')
        resp = json.loads(response.body)
        values = resp.get('result')
        self.assertEqual(values.get('status'), False, response)
        self.assertEqual(values.get('error').get('code'), 410, response)

    def test_reporting_show(self):
        # set reporting policy:
        policy_params = {'name': 'test_init_token_1',
                         'scope': 'reporting',
                         'action': 'token_total',
                         'user': '*',
                         'realm': '*',
                         }
        self.create_policy(policy_params)

        # set reporting access policy:
        policy_params = {'name': 'test_report_show',
                 'scope': 'reporting.access',
                 'action': 'show',
                 'user': '*',
                 'realm': 'mymixrealm, myotherrealm',
                 }
        self.create_policy(policy_params)

        self.create_token(serial='0041', realm='mydefrealm', user='hans')
        self.create_token(serial='0042', user='hans')
        self.create_token(serial='0043', realm='mymixrealm', user='hans',
                          active=False)
        self.create_token(serial='0044', realm='mydefrealm', user='hans')
        self.create_token(serial='0045', realm='mydefrealm', user='lorca')
        self.create_token(serial='0046', realm='myotherrealm')

        response = self.make_authenticated_request(controller='reporting',
                                                   action='show')
        resp = json.loads(response.body)
        self.assertEqual(resp.get('result').get('status'), True, response)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('resultset').get('report_rows'), 3, response)
