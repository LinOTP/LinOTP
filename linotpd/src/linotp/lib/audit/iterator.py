# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

import logging
log = logging.getLogger(__name__)
try:
    import json
except ImportError: # pragma: no cover
    import simplejson as json

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
                    self._search_dict[key] = value
                log.debug(self._search_dict)
            else:
                self._search_dict[param['qtype']] = param["query"]
        else:
            for k, v in param.items():
                self._search_dict[k] = v

        log.debug("[search] search_dict: %s" % self._search_dict)

        if 'page' in param:
            page = param.get('page', '1') or '1'
            self.page = int(page)
            self._rp_dict['page'] = self.page

        if 'rp' in param:
            self._rp_dict['rp'] = param.get('rp', '15') or '15'

        self._rp_dict['sortname'] = param.get('sortname')
        self._rp_dict['sortorder'] = param.get('sortorder')
        log.debug("[search] rp_dict: %s" % self._rp_dict)

        if user:
            self._search_dict['user'] = user.login
            self._search_dict['realm'] = user.realm


        self.audit_search_iter = self._audit.searchQuery(self._search_dict,
                                                   rp_dict=self._rp_dict)

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
        self.audit_query = audit_query
        self.result = self.audit_query.audit_search_iter
        self.page = self.audit_query.page
        self.i = 0
        self.closed = False

    def next(self):
        res = ""
        if self.i == 0:
            res = '{ "page": %d, "rows": [' % int(self.page)
            self.i = 1
        else:
            res = ', '
            self.i = self.i + 1

        try:
            row_data = self.result.next()
            entry = self.audit_query.get_entry(row_data)
            res = "%s %s" % (res,json.dumps(entry, indent=3))

        except StopIteration as exx:
            if self.closed == False:
                res = '], "total": %d }' % self.audit_query.get_total()
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
        self.audit_query = audit_query
        self.result = self.audit_query.audit_search_iter
        self.page = self.audit_query.page
        self.i = 0
        self.closed = False
        self.delimiter = delimiter


    def next(self):
        """
        Generator method (i.e. returns a generator by using 'yield')
        """
        res = ""
        try:
            row_data = self.result.next()
            entry = self.audit_query.get_entry(row_data)
            result = ""
            if self.i == 0 and self.audit_query.headers:
                row = entry.get('data', [])
                r_str = json.dumps(row, ensure_ascii=False)[1:-1]
                result += r_str
                result += "\n"
            row = []
            raw_row = entry.get('cell', [])
            ## we must escape some dump entries, which destroy the
            ## import of the csv data - like SMSProviderConfig 8-(
            for row_entry in raw_row:
                if type(row_entry) in (str, unicode):
                    row_entry = row_entry.replace('\"', "'")
                row.append(row_entry)
            r_str = json.dumps(row, ensure_ascii=False)[1:-1]
            res = (result + r_str + "\n").encode('utf-8')
            self.i = self.i + 1

        except StopIteration as exx:
            if self.closed == False:
                res = "\n"
                self.closed = True
            else:
                log.info("returned %d entries" % self.i)
                raise exx

        return res

    def __iter__(self):
        return self

###eof#########################################################################
