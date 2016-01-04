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
""" the iterators for the audit objects """

import sys

try:
    import json
except ImportError: # pragma: no cover
    import simplejson as json


import linotp.lib.crypt
import logging
log = logging.getLogger(__name__)


class AuditQuery(object):
    """ build the the audit query and return result iterator
    """
    def __init__(self, param, audit, user=None, columns=None):
        self.page = 1
        self.headers = False
        self._columns = None
        self._audit = audit
        self._search_dict = {}
        self._rp_dict = {}

        self.audit = audit

        if 'headers' in param:
            self.headers = True

        if columns:
            # Explicit list of what columns to return
            self._columns = columns
        else:
            # Use all columns
            self._columns = ['number',
                            'date',
                            'sig_check',
                            'missing_line',
                            'action',
                            'success',
                            'serial',
                            'token_type',
                            'user',
                            'realm',
                            'administrator',
                            'action_detail',
                            'info',
                            'linotp_server',
                            'client',
                            'log_level',
                             'clearance_level'
                                     ]

        if "query" in param:
            if "extsearch" == param['qtype']:
                # search patterns are delimited with ;
                search_list = param['query'].split(";")
                for s in search_list:
                    log.debug(s)
                    key, e, value = s.partition("=")
                    key = key.strip()
                    value = value.strip()

                    ## unicode escape search parameter to match
                    ## encoding in db, which stores audit
                    ## entries in escaped format
                    value = linotp.lib.crypt.uencode(value)
                    self._search_dict[key] = value
                log.debug(self._search_dict)
            else:
                ## unicode escape search parameter to match
                ## encoding in db, which stores audit
                ## entries in escaped format
                value = param["query"]
                value = linotp.lib.crypt.uencode(value)
                self._search_dict[param['qtype']] = value
        else:
            for key, value in param.items():
                ## unicode escape search parameter to match
                ## encoding in db, which stores audit
                ## entries in escaped format
                value = linotp.lib.crypt.uencode(value)
                self._search_dict[key] = value

        log.debug("[search] search_dict: %s" % self._search_dict)

        if 'page' in param:
            try:
                self.page = int(param.get('page', '1') or '1')
                if self.page < 0 or self.page > sys.maxint:
                    self.page = 1
            except ValueError:
                self.page = 1
            self._rp_dict['page'] = self.page

        # verify that rows per page is uint
        if 'rp' in param:
            try:
                rp = int(param.get('rp', '15') or '15')
                if rp < 0 or rp > sys.maxint:
                    rp = 15
            except ValueError:
                rp = 15
            self._rp_dict['rp'] = "%d" % rp

        self._rp_dict['sortname'] = param.get('sortname')

        # verify sort order: could be one of ['asc', 'desc']
        sortorder = param.get('sortorder', 'asc') or 'asc'
        if sortorder not in ['desc', 'asc']:
            sortorder = 'asc'
        self._rp_dict['sortorder'] = sortorder

        log.debug("[search] rp_dict: %s" % self._rp_dict)

        if user:
            self._search_dict['user'] = user.login
            self._search_dict['realm'] = user.realm

        return

    def get_page(self):
        return self.page

    def with_headers(self):
        return self.headers

    def get_headers(self):
        return self._columns

    def get_query_result(self):

        self.audit_search = self._audit.searchQuery(self._search_dict,
                                                   rp_dict=self._rp_dict)
        return self.audit_search

    def get_entry(self, row):
        entry = {}
        if type(row) != dict:
            ## convert table data to dict!
            row = self._audit.row2dict(row)
        if 'number' in row:
            cell = []
            for col in self._columns:
                # In the previous implementation there were two conflicting ways
                # of handling the case where 'col' doesn't exist in 'row'. When
                # exporting all columns it was implemented like this: row.get(col, '')
                # When exporting only selected columns like this: row.get(col)
                # In the second case None is returned which in JSON translates as
                # null.
                # In order to differentiate between the empty string (which could be
                # a valid value for most fields) and non-existence I chose the second
                # option. If this causes problems, the issue has to be revisited.
                cell.append(row.get(col))
            entry = {'id': row['number'],
                     'cell': cell}
            if self.headers is True:
                entry['data'] = self._columns

        return entry

    def get_total(self):
        return self._audit.getTotal(self._search_dict)

class JSONAuditIterator(object):
    """
    default audit output generator in json format
    """

    def __init__(self, audit_query):
        '''
        create the iterator from the AuditQuery object
        '''
        self.audit_query = audit_query
        self.result = iter(audit_query.get_query_result())
        self.page = audit_query.get_page()
        self.i = 0
        self.closed = False

    def next(self):
        """
        iterator callback for the response handler
        """
        res = ""
        prefix = ""
        if self.i == 0:
            prefix = '{ "page": %d, "rows": [' % int(self.page)
            res = prefix
            self.i = 1
        else:
            res = ', '
            self.i = self.i + 1

        try:
            row_data = self.result.next()
            entry = self.audit_query.get_entry(row_data)
            res = "%s %s" % (res, json.dumps(entry, indent=3))

        except StopIteration as exx:
            if self.closed == False:
                res = '%s ], "total": %d }' % (prefix, self.audit_query.get_total())
                self.closed = True
            else:
                log.info("returned %d entries" % self.i)
                raise exx

        return res

    def __iter__(self):
        return self

class CSVAuditIterator(object):
    """
    create cvs output by iterating over result
    """

    def __init__(self, audit_query, delimiter):
        '''
        create the iterator from the AuditQuery object
        '''
        self.audit_query = audit_query
        self.result = iter(audit_query.get_query_result())
        self.page = audit_query.get_page()

        self.i = 0
        self.closed = False
        self.delimiter = delimiter


    def next(self):
        """
        iterator callback for the response handler
        """
        res = ""
        try:

            headers = ""
            if self.i == 0 and self.audit_query.with_headers():
                headers = "%s\n" % json.dumps(self.audit_query.get_headers(),
                                               ensure_ascii=False)[1:-1]
                res = headers

            row_data = self.result.next()
            entry = self.audit_query.get_entry(row_data)

            raw_row = entry.get('cell', [])

        ## we must escape some dump entries, which destroy the
        ## import of the csv data - like SMSProviderConfig 8-(
            row = []
            for row_entry in raw_row:
                if type(row_entry) in (str, unicode):
                    row_entry = row_entry.replace('\"', "'")
                row.append(row_entry)

            r_str = json.dumps(row, ensure_ascii=False)[1:-1]
            res = (headers + r_str + "\n").encode('utf-8')
            self.i = self.i + 1

        except StopIteration as exx:
            if self.closed == False:
                res = "%s\n" % res
                self.closed = True
            else:
                log.info("returned %d entries" % self.i)
                raise exx

        return res

    def __iter__(self):
        return self

###eof#########################################################################
