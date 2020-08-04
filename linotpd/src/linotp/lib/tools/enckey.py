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

import os
import tempfile
import click

KEY_COUNT = 3
KEY_LENGTH = 32


def create_secret_key(filename):
    """Creates a LinOTP secret file to encrypt and decrypt values in database

    The key file is used via the default security provider to encrypt
    token seeds, configuration values...

    The key file contains 3 key of length 256 bit (32 Byte) each.
    """

    with tempfile.NamedTemporaryFile(mode='wb',
                                     dir=os.path.dirname(filename),
                                     delete=False) as f:
        os.fchmod(f.fileno(), 0o400)
        f.write(os.urandom(KEY_COUNT * KEY_LENGTH))
    os.replace(f.name, filename)     # atomic rename, since Python 3.3
