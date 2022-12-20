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
import logging

from datetime import datetime
from datetime import timedelta
from pylons import config
from sqlalchemy import engine_from_config
from sqlalchemy.orm import scoped_session, sessionmaker

from freezegun import freeze_time

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

# --------------------------------------------------------------------------- --
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

# --------------------------------------------------------------------------- --
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

        Session = None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False,
                                                  autoflush=True))
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

        Session = None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False,
                                                  autoflush=True))
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

        Session = None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False,
                                                  autoflush=True))
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
        Session = None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False,
                                                  autoflush=True))
            Session.configure(bind=engine)

            # create table entries
            today = datetime.now()
            yesterday = today - timedelta(days=1)
            two_days_ago = today - timedelta(days=2)

            # create old reports:
            report_2 = Reporting(timestamp=two_days_ago,
                                 event='token_init',
                                 realm='mydefrealm',
                                 parameter='active',
                                 count=1)
            report_1 = Reporting(timestamp=yesterday,
                                 event='token_init',
                                 realm='mydefrealm',
                                 parameter='active',
                                 count=2)
            report_0 = Reporting(event='token_init',
                                 realm='mydefrealm',
                                 parameter='active',
                                 count=3)
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
        Session = None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False,
                                                  autoflush=True))
            Session.configure(bind=engine)

            # check if table is empty
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 0, table_content)

            # create table entries
            today = datetime.now()
            yesterday = today - timedelta(days=1)

            report_1 = Reporting(timestamp=yesterday,
                                 event='token_init',
                                 realm='mydefrealm',
                                 parameter='active',
                                 count=1)
            report_2 = Reporting(event='token_init',
                                 realm='mydefrealm',
                                 parameter='active',
                                 count=2)
            Session.add(report_1)
            Session.add(report_2)
            Session.commit()

            # check if reports are in database
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 2, table_content)

            # delete reports
            response = self.make_authenticated_request(
                controller='reporting',
                action='delete_all',
                params={'realm': '*', 'status': 'active'})
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
        Session = None
        try:
            engine = engine_from_config(config, 'sqlalchemy.')
            Session = scoped_session(sessionmaker(autocommit=False,
                                                  autoflush=True))
            Session.configure(bind=engine)
            # check if new entry was created in reporting table
            table_content = Session.query(Reporting).count()
            self.assertEqual(table_content, 1, table_content)
        finally:
            if Session:
                Session.close()

    def test_reporting_period(self):
        """
        test reporting/period

        we create an old entry ahead of all the others

        date                | serial |   realm      |  assigned  |  active
        ------------------------------------------------------------------
        2019-08-04 00:00:01 | 0001 | mydefrealm     | hans      |   y

        - we add a token per 2 days starting at 2020-02-20
          the last day is the 2020-03-01:

        date                | serial |   realm      |  assigned  |  active
        ------------------------------------------------------------------
        2020-02-20 00:00:01 | 0031 | mydefrealm     | hans      |   y
        2020-02-22 00:00:01 | 0032 | (mydefrealm)   | hans      |   n
        2020-02-24 00:00:01 | 0033 | mydefrealm     |           |   n
        2020-02-26 00:00:01 | 0034 | mydefrealm     | lorca     |   y
        2020-02-28 00:00:01 | 0035 | myotherrealm   |           |   y
        2020-03-01 00:00:01 | 0036 | mymixrealm     | hans      |   n

        periods for two realms: mydefrealm and mymixrealm

        # A: include all days - no 'from' and no 'to'
        from         - to           |realm:      | t| ac|nac| as|uas|
        -------------+--------------+--------------------------------------
        (1970-01-01) - (2020-03-01) | mydefrealm | 4| 2 | 2 | 3 | 1
        (1970-01-01) - (2020-03-01) | mymixrealm | 2| 1 | 1 | 2 | N

        # B: open ended: from = '2020-02-20' - no 'to'
        from       - to            |realm:      | t| ac|nac| as|uas|
        -----------+---------------+--------------------------------------
        2020-02-20 - (2020-03-01)  | mydefrealm | 4| 2 | 2 | 3 | 1
        2020-02-20 - (2020-03-01)  | mymixrealm | 2| 1 | 2 | 2 | 0

        # C: exclude last date: no 'from' - 'to': '2020-03-01'
        from         - to         |realm:      | t| ac|nac| as|uas|
        -------------+------------+--------------------------------------
        (1970-01-01) - 2020-03-01 | mydefrealm | 4| 2 | 2 | 3 | 1
        (1970-01-01) - 2020-03-01 | mymixrealm | 1| 1 | 1 | 1 | N

        # D: only the first day, 2020-02-20 - 'to' excludes 2020-02-22
        # 'from' 2020-02-20 - 'to' 2020-02-22
        from       - to           |realm:      | t| ac|nac| as|uas|
        -----------+--------------+--------------------------------------
        2020-02-21 - 2020-02-22   | mydefrealm | 1| 1 | N | 1 | N
        2020-02-21 - 2020-02-22   | mymixrealm | 1| 1 | 0 | 1 | 0


        """

        # ------------------------------------------------------------------ --

        # setu reporting policy

        policy_params = {
            'name': 'test_maximum',
            'scope': 'reporting',
            'action': (
                'token_total, '
                'token_status=active, token_status=inactive, '
                'token_status=assigned, token_status=unassigned'
                ),
            'user': '*',
            'realm': 'mydefrealm,mymixrealm',
        }
        self.create_policy(policy_params)

        # ------------------------------------------------------------------ --

        # create all tokens and events

        fix_date = datetime.strptime(
            '2020-02-20  00:00:01', '%Y-%m-%d  %H:%M:%S'
            )

        # create an initial fallback entry if there is no entry found
        with freeze_time(fix_date - timedelta(days=200)):
            self.create_token(serial='0001', realm='mymixrealm', user='max1',
                              active=False)

        with freeze_time(fix_date):
            self.create_token(serial='0031', realm='mydefrealm', user='hans')
        with freeze_time(fix_date + timedelta(days=2)):
            self.create_token(serial='0032', user='hans', active=False)
        with freeze_time(fix_date + timedelta(days=4)):
            self.create_token(serial='0033', realm='mydefrealm', active=False)
        with freeze_time(fix_date + timedelta(days=6)):
            self.create_token(serial='0034', realm='mydefrealm', user='lorca')
        with freeze_time(fix_date + timedelta(days=8)):
            self.create_token(serial='0035', realm='myotherrealm')
        with freeze_time(fix_date + timedelta(days=10)):
            self.create_token(serial='0036', realm='mymixrealm', user='hans',
                              active=False)

        # ------------------------------------------------------------------ --

        # run reportings

        with freeze_time(fix_date + timedelta(days=10)):

            # 0.a: checking the reporting borders
            # - up to the first entry 2019-08-04, thus there should be only
            #   null's in the response

            params = {
                'realms': 'mydefrealm, mymixrealm',
                'from': '1970-03-01',
                'to': '2019-08-04',
                'status': 'total,active,inactive,assigned,unassigned',
            }
            response = self.make_authenticated_request(
                controller='reporting', action='period', params=params
                )

            realms = {}
            for realm in response.json['result']['value']['realms']:
                realms[realm['name']] = realm

            assert realms['mydefrealm']['maxtokencount'] == {
                'total': None,
                'active': None, 'assigned': None,
                'unassigned': None, 'inactive': None
                }
            assert realms['mymixrealm']['maxtokencount'] == {
                'total': None,
                'active': None, 'assigned': None,
                'unassigned': None, 'inactive': None
                }

            # 0.b: checking the reporting borders
            # - the first entry 2019-08-04 only, thus there should be only
            #   null's in the response for the mydefrealm realm and
            #   mymixrealm has all events but not the unassigned

            params = {
                'realms': 'mydefrealm, mymixrealm',
                'from': '2019-08-04',
                'to': '2019-09-04',
                'status': 'total,active,inactive,assigned,unassigned',
            }
            response = self.make_authenticated_request(
                controller='reporting', action='period', params=params
                )

            realms = {}
            for realm in response.json['result']['value']['realms']:
                realms[realm['name']] = realm

            assert realms['mydefrealm']['maxtokencount'] == {
                'total': None,
                'active': None, 'assigned': None,
                'unassigned': None, 'inactive': None
                }

            # enroll and deactivate are two events thus we have one active and
            # one inactive event, but no unassigned, as the token was initally
            # assigned
            assert realms['mymixrealm']['maxtokencount'] == {
                'total': 1,
                'active': 1, 'assigned': 1,
                'unassigned': 0, 'inactive': 1
                }

            # -------------------------------------------------------------- --

            # A: include all days - no 'from' and no 'to'

            params = {
                'realms': 'mydefrealm, mymixrealm',
                'status': 'total,active,inactive,assigned,unassigned',
            }
            response = self.make_authenticated_request(
                controller='reporting', action='period', params=params
                )

            realms = {}
            for realm in response.json['result']['value']['realms']:
                realms[realm['name']] = realm

            assert realms['mydefrealm']['maxtokencount'] == {
                'total': 4,
                'active': 2, 'assigned': 3,
                'unassigned': 1, 'inactive': 2
                }
            assert realms['mymixrealm']['maxtokencount'] == {
                'total': 2,
                'active': 1, 'assigned': 2,
                'unassigned': 0, 'inactive': 2
                }

            # -------------------------------------------------------------- --

            # B: open ended: from = '2020-02-20' - no 'to'

            params = {
                'realms': 'mydefrealm, mymixrealm',
                'from': '2020-02-20',
                'status': 'total,active,inactive,assigned,unassigned',
            }
            response = self.make_authenticated_request(
                controller='reporting', action='period', params=params
                )

            realms = {}
            for realm in response.json['result']['value']['realms']:
                realms[realm['name']] = realm

            assert realms['mydefrealm']['maxtokencount'] == {
                'total': 4,
                'active': 2, 'assigned': 3,
                'unassigned': 1, 'inactive': 2
                }
            assert realms['mymixrealm']['maxtokencount'] == {
                'total': 2,
                'active': 1, 'assigned': 2,
                'unassigned': 0, 'inactive': 2
                }
            # -------------------------------------------------------------- --

            # C: exclude last date: no 'from' - 'to': '2020-03-01'

            params = {
                'realms': 'mydefrealm, mymixrealm',
                'to': '2020-03-01',
                'status': 'total,active,inactive,assigned,unassigned',
            }
            response = self.make_authenticated_request(
                controller='reporting', action='period', params=params
                )

            realms = {}
            for realm in response.json['result']['value']['realms']:
                realms[realm['name']] = realm

            assert realms['mydefrealm']['maxtokencount'] == {
                'total': 4,
                'active': 2, 'assigned': 3,
                'unassigned': 1, 'inactive': 2
                }
            assert realms['mymixrealm']['maxtokencount'] == {
                'total': 1,
                'active': 1, 'assigned': 1,
                'unassigned': 0, 'inactive': 1
                }

            # -------------------------------------------------------------- --

            # D: only the first day, 2020-02-20 - 'to' excludes 2020-02-22

            params = {
                'realms': 'mydefrealm, mymixrealm',
                'from': '2020-02-20',
                'to': '2020-02-22',
                'status': 'total,active,inactive,assigned,unassigned',
            }
            response = self.make_authenticated_request(
                controller='reporting', action='period', params=params
                )

            realms = {}
            for realm in response.json['result']['value']['realms']:
                realms[realm['name']] = realm

            assert realms['mydefrealm']['maxtokencount'] == {
                'total': 1,
                'active': 1, 'assigned': 1,
                'unassigned': 0, 'inactive': 0
                }
            assert realms['mymixrealm']['maxtokencount'] == {
                'total': 1,
                'active': 1, 'assigned': 1,
                'unassigned': 0, 'inactive': 0
                }

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
        self.assertEqual(resp.get('detail').get('report_rows'), 3, response)
        self.assertEqual(resp.get('result').get('status'), True, response)
        values = resp.get('result').get('value')
        self.assertEqual(values[2].get('count'), 1, response)

        # test csv output

        response = self.make_authenticated_request(controller='reporting',
                                                   action='show',
                                                   params={'outform': 'csv'})
        self.assertTrue('1, "myotherrealm", "", ' in response, response)
        self.assertTrue('"", "", "", "total", "token_init", ' in response,
                        response)

    def test_reporting_show_paging(self):
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
                         'realm': '*',
                         }
        self.create_policy(policy_params)

        for i in range(0, 25):
            self.create_token(serial='005'+str(2*i),
                              realm='mydefrealm',
                              user='lorca')
            self.create_token(serial='005'+str(2*i+1),
                              realm='mymixrealm',
                              user='hans',)

        page_value = 3
        pagesize_value = 12
        parameter = {
            'page': page_value,
            'pagesize': pagesize_value
        }
        response = self.make_authenticated_request(controller='reporting',
                                                   action='show',
                                                   params=parameter)
        resp = json.loads(response.body)
        self.assertEqual(resp.get('detail').get('report_rows'), 50, response)
        self.assertEqual(resp.get('detail').get('page'), page_value, response)
        self.assertEqual(resp.get('detail').get('pagesize'), pagesize_value,
                         response)

        self.assertEqual(resp.get('result').get('status'), True, response)
        values = resp.get('result').get('value')
        self.assertEqual(values[2].get('count'), 14, response)

        timestamp = values[10].get('timestamp')

        # test csv output
        parameter['outform'] = 'csv'
        response = self.make_authenticated_request(controller='reporting',
                                                   action='show',
                                                   params=parameter)
        line = '18, "mydefrealm", "", "%s", "", "", "", "total",' \
               ' "token_init"' % str(timestamp)
        self.assertTrue(line in response, response)
        resp = response.body.splitlines()
        self.assertTrue(len(resp) is pagesize_value + 1)
