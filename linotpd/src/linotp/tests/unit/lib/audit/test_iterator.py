# -*- coding: utf-8 -*-

import unittest
from mock import MagicMock

try:
    import json
except ImportError:
    import simplejson as json

from linotp.lib.audit.iterator import AuditIterator
from linotp.lib.audit.iterator import CSVAuditIterator
from linotp.lib.audit.iterator import JSONAuditIterator


class AuditIteratorTestCase(unittest.TestCase):
    """
    This class tests the AuditIterator, JSONAuditIterator and CSVAuditIterator
    in isolation (without a server).
    """

    def test_searchQuery_1(self):
        """
        Simply verifies that the external method searchQuery is invoked with
        the right parameters. On a real system the call would most probably
        be received by linotp.lib.audit.SQLAudit
        """
        param = {
            'rp': u'15',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bdf249de541d132903568b763306bb84b59b3fa5ad111',
            'sortorder': u'desc',
            'query': u'',
            'qtype': u'serial',
            'page': u'1'
            }
        audit = MagicMock(spec=["searchQuery"])
        audit_iterator = AuditIterator(param, audit)
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
        param = {
            'rp': u'10',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bde249de541d132903568b767706bb84b59b3fa5ad523',
            'sortorder': u'desc',
            'query': u'se_test_auth',
            'qtype': u'realm',
            'page': u'2'
            }
        audit = MagicMock(spec=["searchQuery"])
        audit_iterator = AuditIterator(param, audit)
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
        param = {
            'rp': u'15',
            'sortname': u'number',
            'session': u'deadbeef00174df8e77bde249de541d132903568b767706bb84b59b3fa5ad523',
            'sortorder': u'desc',
            'query': u'حافظ',
            'qtype': u'user',
            'page': u'1'
            }
        audit = MagicMock(spec=["searchQuery"])
        audit_iterator = AuditIterator(param, audit)
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
        audit_iterator = AuditIterator(param, audit)
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

    def test_row2dict_called(self):
        """
        Verify that audit.row2dict is called when some element returned by
        the searchQuery is no dictionary
        """
        audit = MagicMock(spec=["searchQuery", "row2dict"])
        audit.searchQuery.return_value = iter([None, {'key': 'value'}])
        audit_iterator = AuditIterator({}, audit)
        self.assertEqual(len(list(audit_iterator)), 2)
        audit.searchQuery.assert_called_once_with(
            {},
            rp_dict={
                'rp': '15',
                'sortname': None,
                'sortorder': None
                }
            )
        audit.row2dict.assert_called_once_with(None)

    def test_user_search(self):
        """
        Verify that if 'user' is passed in as a parameter, username and realm
        are added to the search parameters.
        """
        user = MagicMock(spec=["login", "realm"])
        user.login = "hans"
        user.realm = "myrealm"
        audit = MagicMock(spec=["searchQuery"])
        audit.searchQuery.return_value = iter([])
        audit_iterator = AuditIterator(
            {
                'qtype': 'action',
                'query': 'audit/search'
                },
            audit,
            user=user
            )
        self.assertEqual(len(list(audit_iterator)), 0)
        audit.searchQuery.assert_called_once_with(
            {
                'action': 'audit/search',
                'realm': 'myrealm',
                'user': 'hans'
                },
            rp_dict={
                'rp': '15',
                'sortname': None,
                'sortorder': None
                }
            )

    def test_JSONAuditIterator_1(self):
        """
        Verify that the the JSONAuditIterator outputs the expected data given
        certain input values
        """
        param =  {u'user': u'حافظ'}
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
        audit_iterator = AuditIterator(param, audit)
        json_audit_iterator = JSONAuditIterator(audit_iterator)
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
        expected_csv = \
u""""number", "date", "sig_check", "missing_line", "action", "success", "serial", "token_type", "user", "realm", "administrator", "action_detail", "info", "linotp_server", "client", "log_level", "clearance_level"
768, "2014-04-25 11:52:54.243084", "OK", null, "validate/check", "1", "LSSP000120D8", "spass", "حافظ", "se_realm1", "", "", "", "oldjoe", "192.168.33.44", "INFO", 0
764, "2014-04-25 11:52:24.937293", "OK", null, "admin/init", "1", "", "", "حافظ", "se_realm1", "admin", "tokennum = 10", "", "oldjoe", "192.168.33.44", "INFO", 0

"""
        param =  {u'user': u'حافظ', 'headers': ''}
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
        audit_iterator = AuditIterator(param, audit)
        csv_audit_iterator = CSVAuditIterator(audit_iterator, ',')
        result_csv = ""
        for value in csv_audit_iterator:
            result_csv += value
        result_csv = result_csv.decode('utf-8')
        self.assertEqual(expected_csv, result_csv)
