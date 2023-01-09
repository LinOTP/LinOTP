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

import json
import unittest

import pytest
from mock import MagicMock


@pytest.mark.usefixtures("app")
class AuditIteratorTestCase(unittest.TestCase):
    """
    This class tests the AuditQuery, JSONAuditIterator and CSVAuditIterator
    in isolation (without a server).
    """

    def test_00_searchQuery_1(self):
        """
        Simply verifies that the external method searchQuery is invoked with
        the right parameters. On a real system the call would most probably
        be received by linotp.lib.audit.SQLAudit
        """
        from linotp.lib.audit.iterator import AuditQuery

        param = {
            "rp": "15",
            "sortname": "number",
            "session": "deadbeef00174df8e77bdf249de"
            "541d132903568b763306bb84b59b3fa5ad111",
            "sortorder": "desc",
            "query": "",
            "qtype": "serial",
            "page": "1",
        }
        audit = MagicMock(spec=["searchQuery", "getTotal"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        assert len(list(audit_iterator)) == 0
        audit.searchQuery.assert_called_once_with(
            {"serial": ""},
            rp_dict={
                "sortorder": "desc",
                "rp": "15",
                "page": 1,
                "sortname": "number",
            },
        )

    def test_searchQuery_2(self):
        """
        Verify searchQuery parameters.
        Search in realm, 10 per page, second page
        """
        from linotp.lib.audit.iterator import AuditQuery

        param = {
            "rp": "10",
            "sortname": "number",
            "session": "deadbeef00174df8e77bde249de541d132903568b767"
            "706bb84b59b3fa5ad523",
            "sortorder": "desc",
            "query": "se_test_auth",
            "qtype": "realm",
            "page": "2",
        }
        audit = MagicMock(spec=["searchQuery"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        assert len(list(audit_iterator)) == 0
        audit.searchQuery.assert_called_once_with(
            {"realm": "se_test_auth"},
            rp_dict={
                "sortorder": "desc",
                "rp": "10",
                "page": 2,
                "sortname": "number",
            },
        )

    def test_searchQuery_3(self):
        """
        Verify searchQuery parameters.
        Unicode
        """
        from linotp.lib.audit.iterator import AuditQuery

        param = {
            "rp": "15",
            "sortname": "number",
            "session": "deadbeef00174df8e77bde249de541d132903568b767"
            "706bb84b59b3fa5ad523",
            "sortorder": "desc",
            "query": "حافظ",
            "qtype": "user",
            "page": "1",
        }
        audit = MagicMock(spec=["searchQuery"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        assert len(list(audit_iterator)) == 0
        audit.searchQuery.assert_called_once_with(
            {"user": "حافظ"},
            rp_dict={
                "sortorder": "desc",
                "rp": "15",
                "page": 1,
                "sortname": "number",
            },
        )

    def test_searchQuery_4(self):
        """
        Verify searchQuery parameters.
        extended search (extsearch)
        """
        from linotp.lib.audit.iterator import AuditQuery

        param = {
            "rp": "15",
            "sortname": "number",
            "session": "deadbeef00174df8e77bde249de541d132903568b767706bb84b59b3fa5ad523",
            "sortorder": "desc",
            "query": "action=audit/search;success=1;number=730",
            "qtype": "extsearch",
            "page": "1",
        }
        audit = MagicMock(spec=["searchQuery"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        assert len(list(audit_iterator)) == 0
        audit.searchQuery.assert_called_once_with(
            {"action": "audit/search", "number": "730", "success": "1"},
            rp_dict={
                "sortorder": "desc",
                "rp": "15",
                "page": 1,
                "sortname": "number",
            },
        )

    # @unittest.skip("Test is broken. TODO fix it.")
    def test_row2dict_called(self):
        """
        Verify that audit.row2dict is called when some element returned by
        the searchQuery is no dictionary
        """
        from linotp.lib.audit.iterator import AuditQuery

        audit = MagicMock(spec=["searchQuery", "row2dict"])
        audit.searchQuery.return_value = [None, {"key": "value"}]
        audit_query = AuditQuery({}, audit)
        audit_iterator = iter(audit_query.get_query_result())

        rows = 0
        for row in audit_iterator:
            audit_query.get_entry(row)
            rows = rows + 1

        assert rows == 2
        audit.searchQuery.assert_called_once_with(
            {}, rp_dict={"sortname": None, "sortorder": "asc"}
        )
        audit.row2dict.assert_called_once_with(None)
        return

    def test_user_search(self):
        """
        Verify that if 'user' is passed in as a parameter, username and realm
        are added to the search parameters.
        """
        from linotp.lib.audit.iterator import AuditQuery

        user = MagicMock(spec=["login", "realm"])
        user.login = "hans"
        user.realm = "myrealm"
        audit = MagicMock(spec=["searchQuery"])
        audit.searchQuery.return_value = iter([])
        audit_query = AuditQuery(
            {"qtype": "action", "query": "audit/search"}, audit, user=user
        )
        audit_iterator = iter(audit_query.get_query_result())

        assert len(list(audit_iterator)) == 0
        audit.searchQuery.assert_called_once_with(
            {"action": "audit/search", "realm": "myrealm", "user": "hans"},
            rp_dict={
                #                'rp': '15',
                "sortname": None,
                "sortorder": "asc",
            },
        )

        return

    def test_JSONAuditIterator_1(self):
        """
        Verify that the the JSONAuditIterator outputs the expected data given
        certain input values
        """
        from linotp.lib.audit.iterator import AuditQuery, JSONAuditIterator

        param = {"user": "حافظ"}
        next_1 = {
            "info": "",
            "administrator": "",
            "realm": "se_realm1",
            "success": "1",
            "linotp_server": "oldjoe",
            "sig_check": "OK",
            "number": 768,
            "token_type": "spass",
            "action": "validate/check",
            "client": "192.168.33.44",
            "user": "حافظ",
            "clearance_level": 0,
            "action_detail": "",
            "date": "2014-04-25 11:52:54.243084",
            "log_level": "INFO",
            "serial": "LSSP000120D8",
        }
        next_2 = {
            "info": "",
            "administrator": "admin",
            "realm": "se_realm1",
            "success": "1",
            "linotp_server": "oldjoe",
            "sig_check": "OK",
            "number": 764,
            "token_type": "",
            "action": "admin/init",
            "client": "192.168.33.44",
            "user": "حافظ",
            "clearance_level": 0,
            "action_detail": "tokennum = 10",
            "date": "2014-04-25 11:52:24.937293",
            "log_level": "INFO",
            "serial": "",
        }

        audit = MagicMock(spec=["searchQuery", "getTotal"])
        audit.searchQuery.return_value = iter([next_1, next_2])
        audit.getTotal.return_value = 2
        audit_query = AuditQuery(param, audit)
        json_audit_iterator = JSONAuditIterator(audit_query)
        result_json = ""
        for value in json_audit_iterator:
            result_json += value
        expected_json = """{ "page": 1, "rows": [ {
   "cell": [
      768,
      "2014-04-25 11:52:54.243084",
      "OK",
      null,
      "validate/check",
      "1",
      "LSSP000120D8",
      "spass",
      "حافظ",
      "se_realm1",
      "",
      "",
      "",
      "oldjoe",
      "192.168.33.44",
      "INFO",
      0
   ],
   "id": 768
}, {
   "cell": [
      764,
      "2014-04-25 11:52:24.937293",
      "OK",
      null,
      "admin/init",
      "1",
      "",
      "",
      "حافظ",
      "se_realm1",
      "admin",
      "tokennum = 10",
      "",
      "oldjoe",
      "192.168.33.44",
      "INFO",
      0
   ],
   "id": 764
}], "total": 2 }"""
        assert json.loads(result_json) == json.loads(expected_json)

    def test_CSVAuditIterator(self):
        """
        Verify that the the CSVAuditIterator outputs the expected data given
        certain input values
        """
        from linotp.lib.audit.iterator import AuditQuery, CSVAuditIterator

        expected_csv = """"number", "date", "sig_check", "missing_line", "action", "success", "serial", "token_type", "user", "realm", "administrator", "action_detail", "info", "linotp_server", "client", "log_level", "clearance_level"
768, "2014-04-25 11:52:54.243084", "OK", null, "validate/check", "1", "LSSP000120D8", "spass", "حافظ", "se_realm1", "", "", "", "oldjoe", "192.168.33.44", "INFO", 0
764, "2014-04-25 11:52:24.937293", "OK", null, "admin/init", "1", "", "", "حافظ", "se_realm1", "admin", "tokennum = 10", "", "oldjoe", "192.168.33.44", "INFO", 0

"""
        param = {"user": "حافظ", "headers": ""}
        next_1 = {
            "info": "",
            "administrator": "",
            "realm": "se_realm1",
            "success": "1",
            "linotp_server": "oldjoe",
            "sig_check": "OK",
            "number": 768,
            "token_type": "spass",
            "action": "validate/check",
            "client": "192.168.33.44",
            "user": "حافظ",
            "clearance_level": 0,
            "action_detail": "",
            "date": "2014-04-25 11:52:54.243084",
            "log_level": "INFO",
            "serial": "LSSP000120D8",
        }
        next_2 = {
            "info": "",
            "administrator": "admin",
            "realm": "se_realm1",
            "success": "1",
            "linotp_server": "oldjoe",
            "sig_check": "OK",
            "number": 764,
            "token_type": "",
            "action": "admin/init",
            "client": "192.168.33.44",
            "user": "حافظ",
            "clearance_level": 0,
            "action_detail": "tokennum = 10",
            "date": "2014-04-25 11:52:24.937293",
            "log_level": "INFO",
            "serial": "",
        }

        audit = MagicMock(spec=["searchQuery", "getTotal"])
        audit.searchQuery.return_value = iter([next_1, next_2])
        audit.getTotal.return_value = 2
        audit_query = AuditQuery(param, audit)
        csv_audit_iterator = CSVAuditIterator(audit_query, ",")
        result_csv = ""
        for value in csv_audit_iterator:
            result_csv += value
        assert expected_csv == result_csv, "%r \n\n%r" % (
            expected_csv,
            result_csv,
        )

        return
