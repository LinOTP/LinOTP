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
Interface for import handling
"""

import crypt
import base64

from os import urandom


def encrypt_password(password):
    """
    we use crypt type sha512, which is a secure and standard according to:
    http://security.stackexchange.com/questions/20541/\
                     insecure-versions-of-crypt-hashes

    :param password: the plain text password
    :return: the encrypted password
    """

    ctype = '6'
    salt_len = 20

    b_salt = urandom(3 * ((salt_len + 3) // 4))

    # we use base64 charset for salt chars as it is nearly the same
    # charset, if '+' is changed to '.' and the fillchars '=' are
    # striped off

    salt = base64.b64encode(b_salt).strip("=").replace('+', '.')

    # now define the password format by the salt definition

    insalt = '$%s$%s$' % (ctype, salt[0:salt_len])
    encryptedPW = crypt.crypt(password, insalt)

    return encryptedPW



class ImportHandler(object):
    """
    interface for ImportHandler - example implemetation is the SQLImportHandler
    """

    def prepare(self):
        """
        external steps called from the UserImport
        """
        raise NotImplementedError

    def commit(self):
        """
        external steps called from the UserImport
        - within this step the resolver is created
        """
        raise NotImplementedError

    def rollback(self):
        """
        external steps called from the UserImport in case of an error
        """
        raise NotImplementedError

    def close(self):
        """
        external steps called from the UserImport during the finalization
        """
        raise NotImplementedError

    # ---------------------------------------------------------------------- --

    def lookup(self, user):
        """
        the lookup is called during the user import, to look for an
        already existing user - could be used to optimze the user lookup
        """
        raise NotImplementedError

    def add(self, user):
        raise NotImplementedError

    def update(self, former_user, user):
        raise NotImplementedError

    def delete_by_id(self, user_id):
        raise NotImplementedError

    # ---------------------------------------------------------------------- --

    # inner class to process the orm user object

    class User(object):
        pass
