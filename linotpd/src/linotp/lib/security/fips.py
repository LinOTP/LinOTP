# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
fips mode mixin - to overwriting the parent provider methods
                  with dedicated fips compliant (hmac) methods

"""


import logging
import hashlib
import Cryptodome.Hash

from linotp.lib.security.libfips import FipsModule
from linotp.lib.security.libfips import SSLError
from linotp.lib.security.default import DefaultSecurityModule
from linotp.lib.security import FatalHSMException

log = logging.getLogger(__name__)


class FipsSecurityModule(DefaultSecurityModule):

    @classmethod
    def getAdditionalClassConfig(cls):
        return ["DefaultSecurityModule"]

    def __init__(self, config=None, add_conf=None):
        '''
        initialsation of the fips security module

        :param config:  contains the configuration definition
        :type  config:  - dict -

        :return -
        '''
        log.debug("initializing FipsSecurityModule %r: %r", config, add_conf)

        self.name = "fips"

        if 'cryptolib' not in config:
            raise FatalHSMException("Missing config entry: 'cryptolib'")

        try:

            # load the fips module and overwrite the parent digest
            self.fips = FipsModule(config['cryptolib'])

            # we use a map of the currently user hash functions to trigger
            # the corresponding fips hmac method
            self.hmac_func_map = {

                Cryptodome.Hash.SHA1: self.fips.hmac_sha1,
                Cryptodome.Hash.SHA256: self.fips.hmac_sha256,
                Cryptodome.Hash.SHA512: self.fips.hmac_sha512,

                hashlib.sha1: self.fips.hmac_sha1,
                hashlib.sha256: self.fips.hmac_sha256,
                hashlib.sha512: self.fips.hmac_sha512}

        except SSLError as exx:
            raise FatalHSMException("Failed to load library %r" % exx)

        DefaultSecurityModule.__init__(self, add_conf)

    def hmac_digest(self, bkey, data_input, hash_algo):
        """
        call the fips hmac function

        :param bkey: the secret key of the hmac token
        :param data_input: the input data like counter or time
        :param: the hashing algorithm

        :return: the hmac digest
        """

        log.debug("fips_hmac_digest")

        if hash_algo in self.hmac_func_map:
            digest = self.hmac_func_map[hash_algo](bkey, str(data_input))
        else:
            raise Exception('unsupported Hash Algorithm %r' % hash_algo)

        return digest

# eof #########################################################################
