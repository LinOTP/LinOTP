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
"""the iterators for the audit objects"""

import json
import logging
import sys
from math import ceil

log = logging.getLogger(__name__)


class AuditQuery(object):
    """build the the audit query and return result iterator"""

    def __init__(self, param, audit_obj, user=None, columns=None):
        self.headers = "headers" in param
        self._columns = columns or self._get_default_columns()
        self._search_dict = self._build_search_dict(param, user)
        self._rp_dict = self._build_rp_dict(param)
        self.page = self._rp_dict.get("page", 1)

        self.audit_obj = audit_obj
        return

    def _get_default_columns(self):
        return [
            "number",
            "date",
            "sig_check",
            "missing_line",
            "action",
            "success",
            "serial",
            "token_type",
            "user",
            "realm",
            "administrator",
            "action_detail",
            "info",
            "linotp_server",
            "client",
            "log_level",
            "clearance_level",
        ]

    def _build_search_dict(self, param, user):
        search_dict = {}

        if "query" in param:
            if "extsearch" == param["qtype"]:
                search_list = param["query"].split(";")

                for s in search_list:
                    key, _, value = s.partition("=")
                    key, value = key.strip(), value.strip()
                    search_dict[key] = value
            else:
                search_dict[param["qtype"]] = param["query"]
        else:
            search_dict = {key: value for key, value in param.items()}

        if user:
            search_dict["user"] = user.login
            search_dict["realm"] = user.realm

        return search_dict

    def _build_rp_dict(self, param):
        rp_dict = {
            "sortname": param.get("sortname"),
            "sortorder": self._get_sort_order(param.get("sortorder", "asc")),
        }
        if "page" in param:
            rp_dict["page"] = self._parse_int(param.get("page", "1"), 1)
        if "rp" in param:
            rp_dict["rp"] = "%d" % self._parse_int(param.get("rp", "15"), 15)

        return rp_dict

    def _parse_int(self, value, fallback):
        try:
            res = int(value)
            if res < 0 or res > sys.maxsize:
                return fallback
            return res
        except ValueError:
            return fallback

    def _get_sort_order(self, order):
        return "desc" if order == "desc" else "asc"

    def get_page(self):
        return self.page

    def with_headers(self):
        return self.headers

    def get_headers(self):
        return self._columns

    def get_query_result(self):
        self.audit_search = self.audit_obj.searchQuery(
            self._search_dict, rp_dict=self._rp_dict
        )
        return self.audit_search

    def get_entry(self, row):
        entry = {}
        if not isinstance(row, dict):
            # convert table data to dict!
            row = self.audit_obj.row2dict(row)
        if "number" in row:
            cell = [row.get(col) for col in self._columns]
            entry = {"id": row["number"], "cell": cell}
            if self.headers is True:
                entry["data"] = self._columns

        return entry

    def get_total(self):
        return self.audit_obj.getTotal(self._search_dict)

    def get_total_pages(self):
        records_per_page = self._rp_dict.get("rp")
        if not records_per_page:
            return 1
        else:
            if int(records_per_page) < 1:
                return self.get_total()
            return ceil(self.get_total() / int(records_per_page))


class JSONAuditIterator(object):
    """
    default audit output generator in json format
    """

    def __init__(self, audit_query):
        """
        create the iterator from the AuditQuery object
        """
        self.audit_query = audit_query
        self.result = iter(audit_query.get_query_result())
        self.page = audit_query.get_page()
        self.i = 0
        self.closed = False

    def __next__(self):
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
            res = ", "
            self.i = self.i + 1

        try:
            row_data = next(self.result)
            entry = self.audit_query.get_entry(row_data)
            res = "%s %s" % (res, json.dumps(entry, indent=3))

        except StopIteration as exx:
            if self.closed is False:
                res = '%s ], "total": %d }' % (
                    prefix,
                    self.audit_query.get_total(),
                )
                self.closed = True
            else:
                raise exx

        return res

    def __iter__(self):
        return self


class CSVAuditIterator(object):
    """
    create cvs output by iterating over result
    """

    def __init__(self, audit_query, delimiter):
        """
        create the iterator from the AuditQuery object
        """
        self.audit_query = audit_query
        self.result = iter(audit_query.get_query_result())
        self.page = audit_query.get_page()

        self.i = 0
        self.closed = False
        self.delimiter = delimiter

    def __next__(self):
        """
        iterator callback for the response handler
        """
        res = ""
        try:
            headers = ""
            if self.i == 0 and self.audit_query.with_headers():
                headers = (
                    "%s\n"
                    % json.dumps(self.audit_query.get_headers(), ensure_ascii=False)[
                        1:-1
                    ]
                )
                res = headers

            row_data = next(self.result)
            entry = self.audit_query.get_entry(row_data)

            raw_row = entry.get("cell", [])

            # we must escape some dump entries, which destroy the
            # import of the csv data - like SMSProviderConfig 8-(
            row = []
            for row_entry in raw_row:
                if isinstance(row_entry, str):
                    row_entry = row_entry.replace('"', "'")
                row.append(row_entry)

            r_str = json.dumps(row, ensure_ascii=False)[1:-1]
            res = headers + r_str + "\n"
            self.i = self.i + 1

        except StopIteration as exx:
            if self.closed is False:
                res = "%s\n" % res
                self.closed = True
            else:
                raise exx

        return res

    def __iter__(self):
        return self


###eof#########################################################################
