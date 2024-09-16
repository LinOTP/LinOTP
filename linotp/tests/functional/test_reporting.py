# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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

import logging
import os
from datetime import datetime, timedelta

from freezegun import freeze_time
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from linotp.flap import config
from linotp.model.reporting import Reporting
from linotp.tests import TestController

log = logging.getLogger(__name__)


class DBSession(object):
    """db session with  context manager"""

    def __init__(self):
        self.engine = create_engine(config.get("DATABASE_URI"))

    def __enter__(self):
        self.session = scoped_session(
            sessionmaker(autocommit=False, autoflush=True)
        )
        self.session.configure(bind=self.engine)
        return self.session

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.session:
            self.session.close()


class TestReportingController(TestController):
    def setUp(self):
        self.delete_all_policies()

        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_reports()

        super(TestReportingController, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        return

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_reports()
        super(TestReportingController, self).tearDown()

    # --------------------------------------------------------------------------- --
    # Helper functions

    def create_token(
        self, serial="1234567", realm=None, user=None, active=True
    ):
        """
        create an HMAC Token with given parameters

        :param serial:  serial number, must be unique per token and test
        :param realm:   optional: set token realm
        :param user:    optional: assign token to user
        :param active:  optional: if this is False, token will be disabled
        :return: serial of new token
        """
        parameters = {
            "serial": serial,
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "description": "TestToken" + serial,
        }
        if realm:
            parameters["realm"] = realm
        if user:
            parameters["user"] = user

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response
        if active is False:
            response = self.make_admin_request(
                "disable", params={"serial": serial}
            )

            assert '"value": 1' in response, response
        return serial

    def delete_all_reports(self):
        """
        empty table Reporting
        """
        response = self.make_reporting_request(
            action="delete_all",
            params={"realms": "*", "status": "*"},
        )

        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response

    # --------------------------------------------------------------------------- --
    # Tests

    def test_init_token(self):
        # set policy:
        policy_params = {
            "name": "test_init_token",
            "scope": "reporting",
            "action": "token_total",
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }
        self.create_policy(policy_params)

        self.create_token(serial="0001", realm="mymixrealm", user="hans")

        with DBSession() as session:
            table_content = session.query(Reporting).count()
            assert table_content == 1, table_content

    def test_reporting_status_active(self):
        # set policy:
        policy_params = {
            "name": "test_active",
            "scope": "reporting",
            "action": "token_total, token_status=active",
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }
        self.create_policy(policy_params)

        self.create_token(serial="0011", realm="mymixrealm", user="hans")
        self.create_token(serial="0012", user="hans")
        self.create_token(
            serial="0013", realm="mymixrealm", user="hans", active=False
        )
        self.create_token(serial="0014", realm="mydefrealm", user="hans")
        self.create_token(serial="0015", realm="mymixrealm", user="lorca")
        self.create_token(serial="0016", realm="myotherrealm")

        with DBSession() as session:
            # check if new entry was created in reporting table
            table_content = session.query(Reporting).count()
            assert table_content == 12, table_content

        parameters = {"user": "hans"}
        self.make_admin_request("disable", params=parameters)

        with DBSession() as session:
            # check if new entry was created in reporting table
            table_content = session.query(Reporting).filter(
                Reporting.parameter == "active"
            )
            assert table_content.count() == 7, table_content

    def test_multi_actions_in_reporting_policy(self):
        self.delete_all_token()

        # set policy:
        policy_params = {
            "name": "test_multi_actions",
            "scope": "reporting",
            "action": "token_total,token_status=active,token_status=inactive",
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }

        self.create_policy(policy_params)

        self.create_token(serial="0021", realm="mymixrealm", user="hans")

        with DBSession() as session:
            # check if new entry was created in reporting table
            table_content = session.query(Reporting).count()
            assert table_content == 3, table_content

    def test_del_before(self):
        """
        test delete rows from reporting table which are older than date
        """
        self.delete_all_reports()

        today = datetime.now()
        yesterday = today - timedelta(days=1)
        two_days_ago = today - timedelta(days=2)

        # create old reports:
        report_2 = Reporting(
            timestamp=two_days_ago,
            event="token_init",
            realm="mydefrealm",
            parameter="active",
            count=1,
        )
        report_1 = Reporting(
            timestamp=yesterday,
            event="token_init",
            realm="mydefrealm",
            parameter="active",
            count=2,
        )
        report_0 = Reporting(
            event="token_init", realm="mydefrealm", parameter="active", count=3
        )

        with DBSession() as session:
            # check if reports are in database
            session.query(Reporting).delete()
            session.commit()

        with DBSession() as session:
            session.add(report_0)
            session.add(report_1)
            session.add(report_2)
            session.commit()

        with DBSession() as session:
            # check if reports are in database
            table_content = session.query(Reporting).count()
            assert table_content == 3, table_content

        # delete reports
        yest = yesterday.strftime("%Y-%m-%d")
        parameter = {"date": yest, "realms": "*", "status": "active"}
        response = self.make_reporting_request(
            "delete_before", params=parameter
        )
        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response
        assert values.get("value") == 1, response

    def test_delete_all_reports(self):
        with DBSession() as session:
            # check if table is empty
            table_content = session.query(Reporting).count()
            assert table_content == 0, table_content

        # create table entries
        today = datetime.now()
        yesterday = today - timedelta(days=1)

        report_1 = Reporting(
            timestamp=yesterday,
            event="token_init",
            realm="mydefrealm",
            parameter="active",
            count=1,
        )
        report_2 = Reporting(
            event="token_init", realm="mydefrealm", parameter="active", count=2
        )

        with DBSession() as session:
            session.add(report_1)
            session.add(report_2)
            session.commit()

        with DBSession() as session:
            # check if reports are in database
            table_content = session.query(Reporting).count()
            assert table_content == 2, table_content

        # delete reports
        response = self.make_reporting_request(
            "delete_all",
            params={"realm": "*", "status": "active"},
        )

        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response
        assert values.get("value") == 2, response

        with DBSession() as session:
            # check if database table is empty
            table_content = session.query(Reporting).count()
            assert table_content == 0, table_content

    def test_selfservice(self):
        # set policies:
        policy_params = {
            "name": "test_init_token_1",
            "scope": "reporting",
            "action": "token_total",
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }
        self.create_policy(policy_params)

        response = self.make_system_request(
            "setPolicy",
            params={
                "name": "self01",
                "realm": "mydefrealm",
                "scope": "selfservice",
                "action": "enrollHMAC",
            },
        )

        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response
        assert (
            values.get("value").get("setPolicy self01").get("action")
        ), response

        # do userservice request
        self.make_userservice_request(
            action="enroll",
            auth_user=("passthru_user1@myDefRealm", "geheim1"),
            params={
                "serial": "token01",
                "type": "hmac",
                "otpkey": "c4a3923c8d97e03af6a12fa40264c54b8429cf0d",
            },
        )

        with DBSession() as session:
            # check if new entry was created in reporting table
            table_content = session.query(Reporting).count()
            assert table_content == 1, table_content

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
            "name": "test_maximum",
            "scope": "reporting",
            "action": (
                "token_total, "
                "token_status=active, token_status=inactive, "
                "token_status=assigned, token_status=unassigned"
            ),
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }
        self.create_policy(policy_params)

        # ------------------------------------------------------------------ --

        # create all tokens and events

        fix_date = datetime.strptime(
            "2020-02-20  00:00:01", "%Y-%m-%d  %H:%M:%S"
        )

        # create an initial fallback entry if there is no entry found
        with freeze_time(fix_date - timedelta(days=200)):
            self.create_token(
                serial="0001", realm="mymixrealm", user="max1", active=False
            )

        with freeze_time(fix_date):
            self.create_token(serial="0031", realm="mydefrealm", user="hans")
        with freeze_time(fix_date + timedelta(days=2)):
            self.create_token(serial="0032", user="hans", active=False)
        with freeze_time(fix_date + timedelta(days=4)):
            self.create_token(serial="0033", realm="mydefrealm", active=False)
        with freeze_time(fix_date + timedelta(days=6)):
            self.create_token(serial="0034", realm="mydefrealm", user="lorca")
        with freeze_time(fix_date + timedelta(days=8)):
            self.create_token(serial="0035", realm="myotherrealm")
        with freeze_time(fix_date + timedelta(days=10)):
            self.create_token(
                serial="0036", realm="mymixrealm", user="hans", active=False
            )

        # ------------------------------------------------------------------ --

        # run reportings

        with freeze_time(fix_date + timedelta(days=10)):
            # 0.a: checking the reporting borders
            # - up to the first entry 2019-08-04, thus there should be only
            #   null's in the response

            params = {
                "realms": "mydefrealm, mymixrealm",
                "from": "1970-03-01",
                "to": "2019-08-04",
                "status": "total,active,inactive,assigned,unassigned",
            }
            response = self.make_reporting_request("period", params=params)

            realms = {}
            for realm in response.json["result"]["value"]["realms"]:
                realms[realm["name"]] = realm

            assert realms["mydefrealm"]["maxtokencount"] == {
                "total": None,
                "active": None,
                "assigned": None,
                "unassigned": None,
                "inactive": None,
            }
            assert realms["mymixrealm"]["maxtokencount"] == {
                "total": None,
                "active": None,
                "assigned": None,
                "unassigned": None,
                "inactive": None,
            }

            # 0.b: checking the reporting borders
            # - the first entry 2019-08-04 only, thus there should be only
            #   null's in the response for the mydefrealm realm and
            #   mymixrealm has all events but not the unassigned

            params = {
                "realms": "mydefrealm, mymixrealm",
                "from": "2019-08-04",
                "to": "2019-09-04",
                "status": "total,active,inactive,assigned,unassigned",
            }
            response = self.make_reporting_request("period", params=params)

            realms = {}
            for realm in response.json["result"]["value"]["realms"]:
                realms[realm["name"]] = realm

            assert realms["mydefrealm"]["maxtokencount"] == {
                "total": None,
                "active": None,
                "assigned": None,
                "unassigned": None,
                "inactive": None,
            }

            # enroll and deactivate are two events thus we have one active and
            # one inactive event, but no unassigned, as the token was initally
            # assigned
            assert realms["mymixrealm"]["maxtokencount"] == {
                "total": 1,
                "active": 1,
                "assigned": 1,
                "unassigned": 0,
                "inactive": 1,
            }

            # -------------------------------------------------------------- --

            # A: include all days - no 'from' and no 'to'

            params = {
                "realms": "mydefrealm, mymixrealm",
                "status": "total,active,inactive,assigned,unassigned",
            }
            response = self.make_reporting_request("period", params=params)

            realms = {}
            for realm in response.json["result"]["value"]["realms"]:
                realms[realm["name"]] = realm

            assert realms["mydefrealm"]["maxtokencount"] == {
                "total": 4,
                "active": 2,
                "assigned": 3,
                "unassigned": 1,
                "inactive": 2,
            }
            assert realms["mymixrealm"]["maxtokencount"] == {
                "total": 2,
                "active": 1,
                "assigned": 2,
                "unassigned": 0,
                "inactive": 2,
            }

            # -------------------------------------------------------------- --

            # B: open ended: from = '2020-02-20' - no 'to'

            params = {
                "realms": "mydefrealm, mymixrealm",
                "from": "2020-02-20",
                "status": "total,active,inactive,assigned,unassigned",
            }
            response = self.make_reporting_request("period", params=params)

            realms = {}
            for realm in response.json["result"]["value"]["realms"]:
                realms[realm["name"]] = realm

            assert realms["mydefrealm"]["maxtokencount"] == {
                "total": 4,
                "active": 2,
                "assigned": 3,
                "unassigned": 1,
                "inactive": 2,
            }
            assert realms["mymixrealm"]["maxtokencount"] == {
                "total": 2,
                "active": 1,
                "assigned": 2,
                "unassigned": 0,
                "inactive": 2,
            }
            # -------------------------------------------------------------- --

            # C: exclude last date: no 'from' - 'to': '2020-03-01'

            params = {
                "realms": "mydefrealm, mymixrealm",
                "to": "2020-03-01",
                "status": "total,active,inactive,assigned,unassigned",
            }
            response = self.make_reporting_request("period", params=params)

            realms = {}
            for realm in response.json["result"]["value"]["realms"]:
                realms[realm["name"]] = realm

            assert realms["mydefrealm"]["maxtokencount"] == {
                "total": 4,
                "active": 2,
                "assigned": 3,
                "unassigned": 1,
                "inactive": 2,
            }
            assert realms["mymixrealm"]["maxtokencount"] == {
                "total": 1,
                "active": 1,
                "assigned": 1,
                "unassigned": 0,
                "inactive": 1,
            }

            # -------------------------------------------------------------- --

            # D: only the first day, 2020-02-20 - 'to' excludes 2020-02-22

            params = {
                "realms": "mydefrealm, mymixrealm",
                "from": "2020-02-20",
                "to": "2020-02-22",
                "status": "total,active,inactive,assigned,unassigned",
            }
            response = self.make_reporting_request("period", params=params)

            realms = {}
            for realm in response.json["result"]["value"]["realms"]:
                realms[realm["name"]] = realm

            assert realms["mydefrealm"]["maxtokencount"] == {
                "total": 1,
                "active": 1,
                "assigned": 1,
                "unassigned": 0,
                "inactive": 0,
            }
            assert realms["mymixrealm"]["maxtokencount"] == {
                "total": 1,
                "active": 1,
                "assigned": 1,
                "unassigned": 0,
                "inactive": 0,
            }

    def test_reporting_maximum(self):
        """
        test reporting/maximum
        """
        # set policy:
        policy_params = {
            "name": "test_maximum",
            "scope": "reporting",
            "action": "token_total, token_status=active",
            "user": "*",
            "realm": "mydefrealm,mymixrealm",
        }
        self.create_policy(policy_params)

        self.create_token(serial="0031", realm="mydefrealm", user="hans")
        self.create_token(serial="0032", user="hans")
        self.create_token(
            serial="0033", realm="mymixrealm", user="hans", active=False
        )
        self.create_token(serial="0034", realm="mydefrealm", user="hans")
        self.create_token(serial="0035", realm="mydefrealm", user="lorca")
        self.create_token(serial="0036", realm="myotherrealm")

        parameters = {"user": "hans"}
        self.make_admin_request("remove", params=parameters)
        response = self.make_reporting_request(
            "maximum",
            params={"realms": "mydefrealm, mymixrealm"},
        )

        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response
        value = values.get("value")
        assert value.get("mydefrealm").get("total") == 4, response
        assert value.get("mymixrealm").get("total") == 1, response

    def test_reporting_access_policy(self):
        policy_params = {
            "name": "test_report_policy",
            "scope": "reporting.access",
            "action": "maximum",
            "user": "Hans",
            "realm": "*",
        }
        self.create_policy(policy_params)
        response = self.make_reporting_request("maximum")
        resp = response.json
        values = resp.get("result")
        assert values.get("status") == False, response
        assert values.get("error").get("code") == 410, response

    def test_reporting_show_no_realms(self):
        # set reporting policy:
        policy_params = {
            "name": "test_init_token_1",
            "scope": "reporting",
            "action": "token_total",
            "user": "*",
            "realm": "*",
        }
        self.create_policy(policy_params)

        # set reporting access policy:
        policy_params = {
            "name": "test_report_show",
            "scope": "reporting.access",
            "action": "show",
            "user": "*",
            "realm": "*",
        }
        self.create_policy(policy_params)

        self.create_token(serial="0041", realm="mydefrealm", user="hans")
        self.create_token(serial="0042", user="hans")
        self.create_token(
            serial="0043", realm="mymixrealm", user="hans", active=False
        )
        self.create_token(serial="0044", realm="mydefrealm", user="hans")
        self.create_token(serial="0045", realm="mydefrealm", user="lorca")
        self.create_token(serial="0046", realm="myotherrealm")
        # create one token which does not belong to any realm and thus
        # is reported as a /:no realm:/ event
        self.create_token(
            serial="0047",
        )

        response = self.make_reporting_request("show")
        resp = response.json
        assert resp.get("detail").get("report_rows") == 8, response
        assert resp.get("result").get("status"), response
        rows = resp.get("result").get("value")
        all_realms = set()
        for entry in rows:
            all_realms.add(entry["realm"])
        assert "/:no realm:/" in all_realms

    def test_reporting_show(self):
        # set reporting policy:
        policy_params = {
            "name": "test_init_token_1",
            "scope": "reporting",
            "action": "token_total",
            "user": "*",
            "realm": "*",
        }
        self.create_policy(policy_params)

        # set reporting access policy:
        policy_params = {
            "name": "test_report_show",
            "scope": "reporting.access",
            "action": "show",
            "user": "*",
            "realm": "mymixrealm, myotherrealm",
        }
        self.create_policy(policy_params)

        self.create_token(serial="0041", realm="mydefrealm", user="hans")
        self.create_token(serial="0042", user="hans")
        self.create_token(
            serial="0043", realm="mymixrealm", user="hans", active=False
        )
        self.create_token(serial="0044", realm="mydefrealm", user="hans")
        self.create_token(serial="0045", realm="mydefrealm", user="lorca")
        self.create_token(serial="0046", realm="myotherrealm")

        # verify that the realm policy defintion restricts
        # the reported realms:
        #
        # the policy restictes the realms to "mymixrealm, myotherrealm"
        # It is verified that the realm 'mydefrealm'is not included in
        # the output
        # the realm '/:no realm:/' though is shown as request
        # parameter 'realms' parameter is omitted which implies
        # default value '*' for the 'realms' parameter. This is
        # translated into: list(all_allowed_realms | {"/:no realm:/"})

        self.create_token(serial="0047")

        response = self.make_reporting_request("show")
        resp = response.json
        assert resp.get("detail").get("report_rows") == 4, response
        assert resp.get("result").get("status"), response
        values = resp.get("result").get("value")
        assert values[2].get("count") == 1, response

        response = self.make_reporting_request("show")
        resp = response.json
        rows = resp.get("result").get("value")
        all_realms = set()
        for entry in rows:
            all_realms.add(entry["realm"])
        assert "/:no realm:/" in all_realms
        assert "mymixrealm" in all_realms
        assert "mydefrealm" not in all_realms

        # test csv output

        response = self.make_reporting_request(
            "show", params={"outform": "csv"}
        )
        assert (
            '"token_init", "myotherrealm", "total", "", 1, ' in response
        ), response

    def test_reporting_show_paging(self):
        # set reporting policy:
        policy_params = {
            "name": "test_init_token_1",
            "scope": "reporting",
            "action": "token_total",
            "user": "*",
            "realm": "*",
        }
        self.create_policy(policy_params)

        # set reporting access policy:
        policy_params = {
            "name": "test_report_show",
            "scope": "reporting.access",
            "action": "show",
            "user": "*",
            "realm": "*",
        }
        self.create_policy(policy_params)

        for i in range(0, 25):
            self.create_token(
                serial="005" + str(2 * i), realm="mydefrealm", user="lorca"
            )
            self.create_token(
                serial="005" + str(2 * i + 1),
                realm="mymixrealm",
                user="hans",
            )

        page_value = 3
        pagesize_value = 12
        parameter = {"page": page_value, "pagesize": pagesize_value}
        response = self.make_reporting_request("show", params=parameter)
        resp = response.json
        assert resp.get("detail").get("report_rows") == 50, response
        assert resp.get("detail").get("page") == page_value, response
        assert resp.get("detail").get("pagesize") == pagesize_value, response

        assert resp.get("result").get("status"), response
        values = resp.get("result").get("value")
        assert values[2].get("count") == 14, response

        timestamp = values[10].get("timestamp")

        # test csv output
        parameter["outform"] = "csv"
        response = self.make_reporting_request("show", params=parameter)
        line = (
            '"%s", "token_init", "mydefrealm", "total", "", 18, "", "", ""'
            % (str(timestamp),)
        )
        assert line in response, response
        resp = response.body.splitlines()
        assert len(resp) is pagesize_value + 1

    def test_token_user_license(self):
        """
        verify that the token user license check is working
        """

        # -------------------------------------------------------------- --

        # read user based license file

        license_data = None
        license_file = os.path.join(
            self.fixture_path, "linotp2.token_user.pem"
        )

        with open(license_file, "r") as f:
            license_data = f.read()

        # -------------------------------------------------------------- --

        # travel back in time with the, then valid, license

        long_ago = datetime(year=2018, month=11, day=17)

        with freeze_time(long_ago) as frozen_time:
            upload_files = [
                ("license", "linotp2.token_user.pem", license_data)
            ]
            response = self.make_system_request(
                "setSupport", upload_files=upload_files
            )
            assert '"status": true' in response
            assert '"value": true' in response

            response = self.make_system_request("getSupportInfo")
            jresp = response.json
            user_num = jresp.get("result", {}).get("value", {}).get("user-num")

            assert user_num == "4"

            # -------------------------------------------------------------- --

            # activate the reporting

            params = {
                "name": "reporting_test",
                "scope": "reporting",
                "active": True,
                "action": "token_user_total,",
                "user": "*",
                "realm": "*",
            }

            response = self.make_system_request("setPolicy", params=params)
            assert '"status": true' in response
            assert "false" not in response

            # set reporting access policy:

            params = {
                "name": "reporting_show",
                "scope": "reporting.access",
                "active": True,
                "action": "show",
                "user": "*",
                "realm": "*",
            }

            response = self.make_system_request("setPolicy", params=params)
            assert '"status": true' in response
            assert "false" not in response

            # -------------------------------------------------------------- --

            # now add tokens for the users

            for user in ["hans", "rollo", "susi", "horst"]:
                params = {
                    "type": "pw",
                    "user": user + "@myDefRealm",
                    "otpkey": "geheim",
                }

                response = self.make_admin_request("init", params)
                assert '"value": true' in response

            # -------------------------------------------------------------- --

            # and look in the reporting database which now should contain
            # the entry about 4 user based license

            params = {
                "status": "total users",
                "realms": "mydefrealm",
                "date": "2018-11-17",
            }

            response = self.make_reporting_request("show", params=params)

            counters = set()
            for entry in response.json["result"]["value"]:
                counters.add(entry["count"])

            assert max(counters) == 4

            # -------------------------------------------------------------- --

            # step ahead for one more day: 2018-11-18

            frozen_time.tick(delta=timedelta(days=1))

            # -------------------------------------------------------------- --

            # add more tokens for the users

            for user in ["hans", "rollo", "susi", "horst"]:
                params = {
                    "type": "pw",
                    "user": user + "@myDefRealm",
                    "otpkey": "geheim",
                }

                response = self.make_admin_request("init", params)
                assert '"value": true' in response

            # -------------------------------------------------------------- --

            # the reporting database still reports only 4 user based entries

            response = self.make_reporting_request("show")

            counters = set()
            for entry in response.json["result"]["value"]:
                counters.add(entry["count"])

            assert max(counters) == 4

            # -------------------------------------------------------------- --

            # some more monitoring/show parameter tests

            # 1. support for start date filter

            params = {
                "status": "total users",
                "realms": "mydefrealm",
                "date": "2018-11-18",
            }

            response = self.make_reporting_request("show", params=params)

            assert len(response.json["result"]["value"]) == 4, response.json

            # 2. support for wild card '*' on status filter

            params = {
                "status": "*",
                "realms": "mydefrealm",
                "date": "2018-11-18",
            }

            response = self.make_reporting_request("show", params=params)

            assert len(response.json["result"]["value"]) == 4, response.json

            # 3. support for wild card '*' on realms filter

            params = {
                "status": "*",
                "realms": "*",
                "date": "2018-11-18",
            }

            response = self.make_reporting_request("show", params=params)

            assert len(response.json["result"]["value"]) == 4, response.json

            # 4. support for realms filter to be case insensitiv

            params = {
                "status": "*",
                "realms": "myDefRealm",
                "date": "2018-11-18",
            }

            response = self.make_reporting_request("show", params=params)

            assert len(response.json["result"]["value"]) == 4, response.json

    def test_bug_1479_token_enrollment(self):
        """Not really to do with the reporting controller but still a
        possible reporting issue. This could not be reproduced but we're
        leaving the test in, on the off-chance.
        """

        # Set reporting policy
        policy_params = {
            "name": "test_bug_1479",
            "scope": "reporting",
            "action": "token_total, token_user_total, ",
            "user": "*",
            "realm": "*",
            "client": "*",
            "time": "* * * * * *;",
            "active": "True",
        }
        self.create_policy(policy_params)

        parameters = {
            "genkey": "1",
            "type": "totp",
            "hashlib": "sha256",
            "otplen": "6",
        }
        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response

    def test_bug_LINOTP_2086_delete_before(self):
        """
        This test is to show the fix for bug LINOTP_2086 where the user could delete entries
        of realms they did not have access to, because the checked policy scope
        was `reporting` instead of `reporting.access`.
        """
        self.delete_all_reports()

        # set policy to prevent user `admin` from accessing `delete_before` for `mydefrealm`:
        policy_params = {
            "name": "test_delete_before",
            "scope": "reporting.access",
            "action": "*",
            "user": "admin",
            "realm": "mymixrealm",
        }

        self.create_policy(policy_params)

        today = datetime.now()
        yesterday = today - timedelta(days=1)
        two_days_ago = today - timedelta(days=2)

        # create old reports:
        report_2 = Reporting(
            timestamp=two_days_ago,
            event="token_init",
            realm="mydefrealm",
            parameter="active",
            count=1,
        )
        report_1 = Reporting(
            timestamp=yesterday,
            event="token_init",
            realm="mydefrealm",
            parameter="active",
            count=2,
        )
        report_0 = Reporting(
            event="token_init", realm="mydefrealm", parameter="active", count=3
        )

        with DBSession() as session:
            # check if reports are in database
            session.query(Reporting).delete()
            session.commit()

        with DBSession() as session:
            session.add(report_0)
            session.add(report_1)
            session.add(report_2)
            session.commit()

        with DBSession() as session:
            # check if reports are in database
            table_content = session.query(Reporting).count()
            assert table_content == 3, table_content

        # try to delete reports
        today_str = today.strftime("%Y-%m-%d")
        parameter = {"date": today_str, "realms": "*", "status": "active"}
        response = self.make_reporting_request(
            "delete_before", params=parameter
        )

        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response
        assert values.get("value") == 0, response

        with DBSession() as session:
            # check if reports are still in database
            table_content = session.query(Reporting).count()
            assert table_content == 3, table_content

        # Check if we also still can delete
        # Create report
        report_3 = Reporting(
            timestamp=two_days_ago,
            event="token_init",
            realm="mymixrealm",
            parameter="active",
            count=1,
        )
        with DBSession() as session:
            session.add(report_3)
            session.commit()

        with DBSession() as session:
            # check if reports are in database
            table_content = session.query(Reporting).count()
            assert table_content == 4, table_content

        # try to delete reports
        today_str = today.strftime("%Y-%m-%d")
        parameter = {"date": today_str, "realms": "*", "status": "active"}
        response = self.make_reporting_request(
            "delete_before", params=parameter
        )

        resp = response.json
        values = resp.get("result")
        assert values.get("status"), response
        assert values.get("value") == 1, response

        with DBSession() as session:
            # check if reports are still in database
            table_content = session.query(Reporting).count()
            assert table_content == 3, table_content
