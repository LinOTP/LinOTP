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


"""
"""

from linotp.tests import TestController


class TestPoliciesBase(TestController):
    def _read_data(self, data_file):
        """
        helper to read token data files
        """

        file_name = self._get_file_name(data_file)

        with open(file_name, "r") as data_file:
            data = data_file.read()

            return data

    def upload_tokens(
        self, file_name, data=None, params=None, auth_user="admin"
    ):
        """
        helper to upload a token file via admin/loadtokens file upload
        like it is done in the browser

        :param file_name: the name of the token file in the fixtures dir
        :param data: do not read the fixture file and use data instead
        :param params: additional parameters to describe the file type
        :return: the response from LinOTP
        """

        if data is None:
            data = self._read_data(file_name)

        upload_files = [("file", file_name, data)]

        response = self.make_admin_request(
            "loadtokens",
            params=params,
            method="POST",
            upload_files=upload_files,
            auth_user=auth_user,
        )

        return response
