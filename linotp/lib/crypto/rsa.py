# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2020 KeyIdentity GmbH
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
""" methods to handle rsa signature - sign and verify """


import logging

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme

log = logging.getLogger(__name__)


def verify_rsa_signature(
    pub_key: bytes, message: bytes, signature: bytes
) -> bool:
    """
    verify rsa signature

    :param pub_key: the public key as bytes in pem format
    :param message: e.g. the license as string as bytes
    :param signature: e.g. the license signature as bytes
    :return: boolean
    """
    return RSA_Signature(public=pub_key).verify(message, signature)


def create_rsa_signature(priv_key: bytes, message: bytes) -> bytes:
    """
    create rsa signature

    :param priv_key: the private as bytes
    :param message: e.g. the license as string as bytes
    :return: signature in bytes
    """
    return RSA_Signature(private=priv_key).sign(message)


class RSA_Signature:
    """
    encapsulate the signature handling
    which allows to switch the cryptographic implementation
    """

    def __init__(self, private: bytes = None, public: bytes = None):
        """
        instantiate the verifier and signer

        :param private: the public key as bytes in pem format
        :param public: the public key as bytes in pem format

        remark: Must provide a public or private key.
                If a private key is given, sign and verify is possible.
                If a public key is given only verify is possible.
        """
        self.signer = None
        self.verifier = None

        if private:

            private_key = RSA.import_key(private)
            self.signer = PKCS115_SigScheme(private_key)
            self.verifier = self.signer

        if not self.verifier and public:

            public_key = RSA.import_key(public)
            self.verifier = PKCS115_SigScheme(public_key)

        if not self.verifier:
            raise Exception("At least a public or private key is required!")

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        verify a message signature

        :param message: as bytes
        :param signature: as bytes
        :return: boolean, True for matching signature
        """

        if not self.verifier:
            raise Exception("Verifier not initialized!")

        hashed_message = SHA256.new(message)

        try:
            self.verifier.verify(hashed_message, signature)
            return True

        except ValueError as vexx:
            log.debug("Failed to verify signature: %r", vexx)
            return False

        except Exception as exx:
            log.error("Failed to verify signature: %r", exx)
            raise exx

    def sign(self, message: bytes) -> bytes:
        """
        sign a message

        :param message: as bytes
        :return: signature: as bytes
        """

        if not self.signer:
            raise Exception("Signer not initialized!")

        if not self.signer.can_sign():
            raise Exception("unable to sign - signer not initialized?")

        return self.signer.sign(SHA256.new(message))


# eof
