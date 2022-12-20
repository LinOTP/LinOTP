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
    params = dict(
        serial="ABC123",
        action="testAction",
        success="1",
        tokentype="pw",
        user="operator",
        realm="realmtest",
        administrator="admin",
        action_detail="This is a test audit entry",
        info="info entry",
        client="client1",
        log_level="debug",
        clearance_level="1",
    )
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
