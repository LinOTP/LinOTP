#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
Tests the create of audit entries
"""

import unittest
from mock import patch
from linotp.lib.auth.finishtokens import FinishTokens


mocked_context = {'audit': {}}


class TestAuditEntryCase(unittest.TestCase):

    @patch("linotp.lib.auth.finishtokens.context", mocked_context)
    def test_create_audit_entry(self):

        finish_tokens = FinishTokens(
                              valid_tokens=[],
                              challenge_tokens=[],
                              pin_matching_tokens=[],
                              invalid_tokens=[],
                              validation_results={},
                              user=None, options=None,
                              audit_entry={})

        audit_entry = mocked_context['audit']

        # 1.a Test  - no previous 'action detail'

        msg = "no token found!"
        finish_tokens.create_audit_entry(
            action_detail=audit_entry.get('action_detail', msg),
            tokens=[])

        self.assertTrue('action_detail' in mocked_context['audit'])
        self.assertTrue(msg in mocked_context['audit']['action_detail'])

        # 1.b Test  - previous 'action detail' is default

        msg = "Failcounter exceeded!"
        finish_tokens.create_audit_entry(action_detail=msg, tokens=[])

        self.assertTrue('action_detail' in mocked_context['audit'])
        self.assertTrue(msg in mocked_context['audit']['action_detail'])

        # 2. Test  - previous 'action detail' is default

        audit_entry['action_detail'] = "no token found!"
        msg = "no sun, no fun"
        finish_tokens.create_audit_entry(msg, tokens=[])

        self.assertTrue('action_detail' in mocked_context['audit'])
        self.assertTrue(msg in mocked_context['audit']['action_detail'])

        # 3. Test  - previous 'action detail' is default

        audit_entry['action_detail'] = "no sun, no fun"
        finish_tokens.create_audit_entry(audit_entry['action_detail'],
                                         tokens=[])

        self.assertTrue('action_detail' in mocked_context['audit'])
        self.assertTrue("no sun, no fun" in
                        mocked_context['audit']['action_detail'])

        # 4. Test  - no parameter, falling back to 'no token found!'

        audit_entry['action_detail'] = "no sun, no fun"
        msg = "no token found!"
        finish_tokens.create_audit_entry(tokens=[])

        self.assertTrue('action_detail' in mocked_context['audit'])
        self.assertTrue(msg in
                        mocked_context['audit']['action_detail'])

        return
