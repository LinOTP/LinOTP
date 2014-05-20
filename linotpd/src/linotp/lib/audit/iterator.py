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

class AuditIterator(object):

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

        page = param.get('page', None) or None
        if page is not None:
            self.page = int(page)
            self._rp_dict['page'] = self.page

        self._rp_dict['rp'] = param.get('rp', '15') or '15'
        self._rp_dict['sortname'] = param.get('sortname')
        self._rp_dict['sortorder'] = param.get('sortorder')
        log.debug("[search] rp_dict: %s" % self._rp_dict)

        if user:
            self._search_dict['user'] = user.login
            self._search_dict['realm'] = user.realm

    def __iter__(self):
        """
        This method returns a generator that yields dicts of the form
        {'id': ID, 'cell': LIST, 'data': LIST}, each representing a row of the
        SQLAlchemy Iterator.
        """
        # fetch the query iterator
        audit_search_iter = self._audit.searchQuery(self._search_dict,
                                                   rp_dict=self._rp_dict)
        for row in audit_search_iter:
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
            yield entry

    def get_total(self):
        return self._audit.getTotal(self._search_dict)


class JSONAuditIterator(object):
    """
    default audit output generator in json format
    """

    def __init__(self, audit_iterator):
        self.audit_iterator = audit_iterator

    def __iter__(self):
        """
        Generator method (i.e. returns a generator by using 'yield')
        """
        yield '{ "page": %d, "rows": [' % int(self.audit_iterator.page)
        for i, entry in enumerate(self.audit_iterator):
            if i == 0:
                yield " %s" % json.dumps(entry, indent=3)
            else:
                yield ", %s" % json.dumps(entry, indent=3)
        yield '], "total": %d }' % self.audit_iterator.get_total()


class CSVAuditIterator(object):
    """
    create cvs output by iterating over result
    """

    def __init__(self, audit_iterator, delimiter):
        self.audit_iterator = audit_iterator
        self.delimiter = delimiter

    def __iter__(self):
        """
        Generator method (i.e. returns a generator by using 'yield')
        """
        for i, entry in enumerate(self.audit_iterator):
            result = ""
            if i == 0 and self.audit_iterator.headers:
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
            yield (result + r_str + "\n").encode('utf-8')
        yield "\n"

###eof#########################################################################
