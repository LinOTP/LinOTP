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

import sys
if sys.version_info < (2, 7):
    try:
        import unittest2 as unittest
    except ImportError as exc:
        print "You need to install unittest2 on Python 2.6. unittest2 is a "\
              "backport of new unittest features."
        raise exc
else:
    import unittest
from mock import MagicMock

try:
    import json
except ImportError:
    import simplejson as json


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
            'rp': u'15',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bdf249de'
                         '541d132903568b763306bb84b59b3fa5ad111',
            'sortorder': u'desc',
            'query': u'',
            'qtype': u'serial',
            'page': u'1'
            }
        audit = MagicMock(spec=["searchQuery", "getTotal"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        self.assertEqual(len(list(audit_iterator)), 0)
        audit.searchQuery.assert_called_once_with(
            {u'serial': u''},
            rp_dict={
                'sortorder': u'desc',
                'rp': u'15',
                'page': 1,
                'sortname': u'number'
                }
            )

    def test_searchQuery_2(self):
        """
        Verify searchQuery parameters.
        Search in realm, 10 per page, second page
        """
        from linotp.lib.audit.iterator import AuditQuery
        param = {
            'rp': u'10',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bde249de541d132903568b767'
                        '706bb84b59b3fa5ad523',
            'sortorder': u'desc',
            'query': u'se_test_auth',
            'qtype': u'realm',
            'page': u'2'
            }
        audit = MagicMock(spec=["searchQuery"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        self.assertEqual(len(list(audit_iterator)), 0)
        audit.searchQuery.assert_called_once_with(
            {u'realm': u'se_test_auth'},
            rp_dict={
                'sortorder': u'desc',
                'rp': u'10',
                'page': 2,
                'sortname': u'number'
                }
            )

    def test_searchQuery_3(self):
        """
        Verify searchQuery parameters.
        Unicode
        """
        from linotp.lib.audit.iterator import AuditQuery
        param = {
            'rp': u'15',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bde249de541d132903568b767'
                        '706bb84b59b3fa5ad523',
            'sortorder': u'desc',
            'query': u'حافظ',
            'qtype': u'user',
            'page': u'1'
            }
        audit = MagicMock(spec=["searchQuery"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        self.assertEqual(len(list(audit_iterator)), 0)
        audit.searchQuery.assert_called_once_with(
            {u'user': u'حافظ'},
            rp_dict={
                'sortorder': u'desc',
                'rp': u'15',
                'page': 1,
                'sortname': u'number'
                }
            )

    def test_searchQuery_4(self):
        """
        Verify searchQuery parameters.
        extended search (extsearch)
        """
        from linotp.lib.audit.iterator import AuditQuery
        param = {
            'rp': u'15',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bde249de541d132903568b767706bb84b59b3fa5ad523',
            'sortorder': u'desc',
            'query': u'action=audit/search;success=1;number=730',
            'qtype': u'extsearch',
            'page': u'1'
            }
        audit = MagicMock(spec=["searchQuery"])
        audit_query = AuditQuery(param, audit)
        audit_iterator = iter(audit_query.get_query_result())

        self.assertEqual(len(list(audit_iterator)), 0)
        audit.searchQuery.assert_called_once_with(
            {
                u'action': u'audit/search',
                u'number': u'730',
                u'success': u'1'
                },
            rp_dict={
                'sortorder': u'desc',
                'rp': u'15',
                'page': 1,
                'sortname': u'number'
                }
            )

    #@unittest.skip("Test is broken. TODO fix it.")
    def test_row2dict_called(self):
        """
        Verify that audit.row2dict is called when some element returned by
        the searchQuery is no dictionary
        """
        from linotp.lib.audit.iterator import AuditQuery
        audit = MagicMock(spec=["searchQuery", "row2dict"])
        audit.searchQuery.return_value = [None, {'key': 'value'}]
        audit_query = AuditQuery({}, audit)
        audit_iterator = iter(audit_query.get_query_result())

        rows = 0
        for row in audit_iterator:
            audit_query.get_entry(row)
            rows = rows + 1

        self.assertEqual(rows, 2)
        audit.searchQuery.assert_called_once_with(
            {},
            rp_dict={
                'sortname': None,
                'sortorder': 'asc'
                }
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
            {
                'qtype': 'action',
                'query': 'audit/search'
                },
            audit,
            user=user
            )
        audit_iterator = iter(audit_query.get_query_result())

        self.assertEqual(len(list(audit_iterator)), 0)
        audit.searchQuery.assert_called_once_with(
            {
                'action': 'audit/search',
                'realm': 'myrealm',
                'user': 'hans'
                },
            rp_dict={
#                'rp': '15',
                'sortname': None,
                'sortorder': 'asc'
                }
            )

        return

    def test_JSONAuditIterator_1(self):
        """
        Verify that the the JSONAuditIterator outputs the expected data given
        certain input values
        """
        from linotp.lib.audit.iterator import (AuditQuery, JSONAuditIterator)
        param = {u'user': u'حافظ'}
        next_1 = {
            'info': u'',
            'administrator': u'',
            'realm': u'se_realm1',
            'success': u'1',
            'linotp_server': u'oldjoe',
            'sig_check': 'OK',
            'number': 768L,
            'token_type': u'spass',
            'action': u'validate/check',
            'client': u'192.168.33.44',
            'user': u'حافظ',
            'clearance_level': 0L,
            'action_detail': u'',
            'date': '2014-04-25 11:52:54.243084',
            'log_level': u'INFO',
            'serial': u'LSSP000120D8'
            }
        next_2 = {
            'info': u'',
            'administrator': u'admin',
            'realm': u'se_realm1',
            'success': u'1',
            'linotp_server': u'oldjoe',
            'sig_check': 'OK',
            'number': 764L,
            'token_type': u'',
            'action': u'admin/init',
            'client': u'192.168.33.44',
            'user': u'حافظ',
            'clearance_level': 0L,
            'action_detail': u'tokennum = 10',
            'date': '2014-04-25 11:52:24.937293',
            'log_level': u'INFO',
            'serial': u''
            }

        audit = MagicMock(spec=["searchQuery", "getTotal"])
        audit.searchQuery.return_value = iter([next_1, next_2])
        audit.getTotal.return_value = 2
        audit_query = AuditQuery(param, audit)
        json_audit_iterator = JSONAuditIterator(audit_query)
        result_json = ""
        for value in json_audit_iterator:
            result_json += value
        expected_json = \
u"""{ "page": 1, "rows": [ {
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
        self.assertEqual(json.loads(result_json), json.loads(expected_json))

    def test_CSVAuditIterator(self):
        """
        Verify that the the CSVAuditIterator outputs the expected data given
        certain input values
        """
        from linotp.lib.audit.iterator import (AuditQuery, CSVAuditIterator)
        expected_csv = \
u""""number", "date", "sig_check", "missing_line", "action", "success", "serial", "token_type", "user", "realm", "administrator", "action_detail", "info", "linotp_server", "client", "log_level", "clearance_level"
768, "2014-04-25 11:52:54.243084", "OK", null, "validate/check", "1", "LSSP000120D8", "spass", "حافظ", "se_realm1", "", "", "", "oldjoe", "192.168.33.44", "INFO", 0
764, "2014-04-25 11:52:24.937293", "OK", null, "admin/init", "1", "", "", "حافظ", "se_realm1", "admin", "tokennum = 10", "", "oldjoe", "192.168.33.44", "INFO", 0

"""
        param = {u'user': u'حافظ', 'headers': ''}
        next_1 = {
            'info': u'',
            'administrator': u'',
            'realm': u'se_realm1',
            'success': u'1',
            'linotp_server': u'oldjoe',
            'sig_check': 'OK',
            'number': 768L,
            'token_type': u'spass',
            'action': u'validate/check',
            'client': u'192.168.33.44',
            'user': u'حافظ',
            'clearance_level': 0L,
            'action_detail': u'',
            'date': '2014-04-25 11:52:54.243084',
            'log_level': u'INFO',
            'serial': u'LSSP000120D8'
            }
        next_2 = {
            'info': u'',
            'administrator': u'admin',
            'realm': u'se_realm1',
            'success': u'1',
            'linotp_server': u'oldjoe',
            'sig_check': 'OK',
            'number': 764L,
            'token_type': u'',
            'action': u'admin/init',
            'client': u'192.168.33.44',
            'user': u'حافظ',
            'clearance_level': 0L,
            'action_detail': u'tokennum = 10',
            'date': '2014-04-25 11:52:24.937293',
            'log_level': u'INFO',
            'serial': u''
            }

        audit = MagicMock(spec=["searchQuery", "getTotal"])
        audit.searchQuery.return_value = iter([next_1, next_2])
        audit.getTotal.return_value = 2
        audit_query = AuditQuery(param, audit)
        csv_audit_iterator = CSVAuditIterator(audit_query, ',')
        result_csv = ""
        for value in csv_audit_iterator:
            result_csv += value
        result_csv = result_csv.decode('utf-8')
        self.assertEqual(expected_csv, result_csv,
                         "%r \n\n%r" % (expected_csv, result_csv))

        return
