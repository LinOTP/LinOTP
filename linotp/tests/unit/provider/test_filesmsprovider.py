# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP smsprovider.
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

import os
import tempfile

from unittest import TestCase

from linotp.provider.smsprovider.FileSMSProvider import FileSMSProvider

class TestSMS(TestCase):

    def test_filesms_provider(self):
        """ test the file writing """

        # ------------------------------------------------------------------ --

        # setup the file sms provider to write into temporary file

        fsms = FileSMSProvider()
        temp_file = tempfile.NamedTemporaryFile()

        os.path.dirname(temp_file.name)

        config = {
            'file': os.path.basename(temp_file.name),
            'here': os.path.dirname(temp_file.name)
            }
        fsms.loadConfig(config)

        # ------------------------------------------------------------------ --

        # test the standard string message

        message = 'test sms with my favorite otp: 8765 4321'

        fsms._submitMessage('+49 1717 1234 567', message)

        # ------------------------------------------------------------------ --

        # test with bytes as message - supported by internal conversion

        message = b'test sms with my favorite otp: 8765 4321'

        fsms._submitMessage('+49 1717 1234 567', message)

#eof
