# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#


"""
"""

import os
import logging
from linotp.tests import TestController


log = logging.getLogger(__name__)


class TestImportUser(TestController):

    group_id = 'import_user'

    def setUp(self):
        TestController.setUp(self)

    def tearDown(self):

        response = self.delete_users(self.group_id)
        self.assertTrue('"status": true' in response, response)

        return TestController.tearDown(self)

    def delete_users(self, groupid):

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {'groupid': groupid,
                  'resolver': 'user_import',
                  'dryrun': False,
                  'format': 'password',
                  'column_separator': ',',
                  'text_delimiter': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        return response

    def test_import_user(self):
        """
        check that import users will create. update and delete users
        """

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
                  'dryrun': False,
                  'format': 'password',
                  'column_separator': ',',
                  'text_delimiter': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": 0' in response, response)
        self.assertTrue('"created": 0' in response, response)

        def_passwd_file = os.path.join(self.fixture_path, 'def-passwd')

        with open(def_passwd_file, "r") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
                  'dryrun': False,
                  'format': 'password',
                  'column_separator': ',',
                  'text_delimiter': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": 0' in response, response)
        self.assertTrue('"created": 24' in response, response)

        csv_data = content.split('\n')[4:]
        content = '\n'.join(csv_data)
        upload_files = [("file", "user_list", content)]

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": 20' in response, response)
        self.assertTrue('"created": 0' in response, response)
        self.assertTrue('"deleted": 4' in response, response)

        return

    def test_import_user_dryrun(self):
        """
        check that the dryrun does not import a user
        """

        def_passwd_file = os.path.join(self.fixture_path, 'def-passwd')

        with open(def_passwd_file, "r") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
                  'dryrun': True,
                  'format': 'password',
                  'column_separator': ',',
                  'text_delimiter': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": 0' in response, response)
        self.assertTrue('"created": 24' in response, response)

        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
                  'dryrun': True,
                  'format': 'password',
                  'column_separator': ',',
                  'text_delimiter': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": 0' in response, response)
        self.assertTrue('"created": 24' in response, response)

# eof ########################################################################
