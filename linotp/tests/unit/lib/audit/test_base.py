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

"""
Unit tests for audit base
"""

import pytest

from linotp.lib.audit.base import AuditBase, getAudit
from linotp.lib.audit.SQLAudit import Audit


class TestAuditSetup:
    @pytest.mark.app_config(
        {
            "AUDIT_DATABASE_URI": "OFF",
        }
    )
    def test_sqlaudit_off(self, app):
        audit = getAudit()

        # audit object should be a dummy class without implementation
        assert isinstance(audit, AuditBase)

    @pytest.mark.app_config({})
    def test_sqlaudit_sqlaudit(self, app):
        audit = getAudit()

        # audit object should be a database audit
        assert isinstance(audit, Audit)
