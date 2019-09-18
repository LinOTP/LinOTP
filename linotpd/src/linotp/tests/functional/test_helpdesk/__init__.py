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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
#

""" smtp mocking helper """

import smtplib
from mock import patch

class MockedSMTP(object):
    def __init__(self):
        self.patch_smtp = patch('smtplib.SMTP', spec=smtplib.SMTP)

    def __enter__(self):
        mock_smtp_class = self.patch_smtp.start()
        self.mock_smtp_instance = mock_smtp_class.return_value
        return self.mock_smtp_instance

    def __exit__(self, *args, **kwargs):
        self.patch_smtp.stop()