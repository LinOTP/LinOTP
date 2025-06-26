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
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument

import pytest

from linotp.lib.audit.SQLAudit import AuditTable


@pytest.fixture
def auditparams():
    """
    Audit parameter set

    Fixture that provides parameters that can be used to construct
    a test audit log entry
    """
    params = {
        "serial": "ABC123",
        "action": "testAction",
        "success": "1",
        "tokentype": "pw",
        "user": "operator",
        "realm": "realmtest",
        "administrator": "admin",
        "action_detail": "This is a test audit entry",
        "info": "info entry",
        "client": "client1",
        "log_level": "debug",
        "clearance_level": "1",
    }
    return params


@pytest.fixture
def auditrec(auditparams):
    """
    Fixture that provides a test audit entry that can be logged
    """
    return AuditTable(**auditparams)


@pytest.fixture
def search(adminclient):
    """
    Factory fixture that provides a function that can be used
    to submit an audit search.
    """
    # We provide this as a fixture so that we can get access
    # to the app and client fixtures within the function

    def _search(expected_status_code=200, json=True, **params):
        outform = json and "json" or "csv"
        queryparams = dict(params, outform=outform)
        response = adminclient.get("audit/search", query_string=queryparams)
        assert response.status_code == 200

        return response

    return _search


class TestAuditSearch(object):
    def test_audit_json_empty(self, search):
        response = search()
        expected = {"page": 1, "rows": [], "total": 0}

        assert response.json == expected

    def test_audit_csv_empty(self, search):
        response = search(json=False)

        assert response.data == b"\n"

    def test_audit_with_json(self, adminclient, search):
        # GIVEN an empty audit database
        assert not search().json["rows"]

        # WHEN I create an audit record by retrieving the system config
        adminclient.get("/system/getConfig")

        # THEN the operation is logged and can be read by audit/search
        response = search()
        assert response.json["rows"][-1]["cell"][4] == "system/getConfig"

    def test_audit_with_v2(self, adminclient, search):
        # WHEN I create an audit record by retrieving the system config
        adminclient.get("/system/getConfig")

        # THEN the operation is logged and can be read by audit/search
        response = adminclient.get("/api/v2/auditlog/")
        assert (
            "system/getConfig"
            == response.json["result"]["value"]["pageRecords"][0]["action"]
        ), response.json

        # test auditlog can be filtered
        filters = [
            "id",
            "timestamp",
            "serial",
            "action",
            "actionDetail",
            "success",
            "tokenType",
            "user",
            "realm",
            "administrator",
            "info",
            "linotpServer",
            "client",
            "logLevel",
            "clearanceLevel",
        ]
        for filter in filters:
            response = adminclient.get(
                "/api/v2/auditlog/",
                query_string={filter: "Empty response -> filtering works"},
            )
            returned_entries = response.json["result"]["value"]["pageRecords"]
            assert 0 == len(returned_entries), (filter, response.json)

        # test wildcard operator `*`
        response = adminclient.get(
            "/api/v2/auditlog/",
            query_string={"action": "*ystem/getConfi*"},
        )
        returned_entries = response.json["result"]["value"]["pageRecords"]
        assert 1 == len(returned_entries), (filter, response.json)

    def test_audit_with_v2_sorting(self, adminclient, search):
        # create an audit record by retrieving the system config
        adminclient.get("/system/getConfig")
        # create an audit record by retrieving the audit
        adminclient.get("/api/v2/auditlog/")

        # test sort by action asc
        response_asc = adminclient.get(
            "/api/v2/auditlog/",
            query_string={"sortBy": "action", "sortOrder": "asc"},
        )
        returned_entries_asc = response_asc.json["result"]["value"]["pageRecords"]
        assert 2 == len(returned_entries_asc), response_asc.json
        assert "api/v2/auditlog/" == returned_entries_asc[0]["action"], (
            returned_entries_asc
        )

        # test sort by action desc
        response_desc = adminclient.get(
            "/api/v2/auditlog/",
            query_string={"sortBy": "action", "sortOrder": "desc"},
        )
        returned_entries_desc = response_desc.json["result"]["value"]["pageRecords"]
        assert 3 == len(returned_entries_desc), response_desc.json
        assert "system/getConfig" == returned_entries_desc[0]["action"], (
            returned_entries_desc
        )


# class TestAuditRecord(object):
#     """
#     Test audit records written to the database
#     """
#     param_names=None
#     params=None
#     rec=None
#     loggedrec=None

#     @pytest.fixture(autouse=True)
#     def _setup_record(self, app, search, auditparams, auditrec):
#         self.param_names = auditparams.keys()
#         self.params = auditparams
#         self.rec = auditrec
#         self.loggedrec = search(json=False)

#     def test_record_parameters(self):
#         """Check that all parameters are in the record"""
#         for name in self.param_names:
#             assert getattr(self.rec, name) == self.params[name]

#     def test_record_in_db(self):
#         """Check the audit record was written"""
#         assert len(self.loggedrec) == 1

#     def test_db_values(self):
#         """Check the values of the written record"""
#         for name in self.param_names:
#             assert getattr(self.loggedrec, name) == self.params[name]
