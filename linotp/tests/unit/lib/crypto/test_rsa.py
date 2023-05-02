# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2020 KeyIdentity GmbH
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
""" test the linotp.lib.crypto.rsa cryptography """

import base64
import unittest

from linotp.lib.crypto.rsa import (
    RSA_Signature,
    create_rsa_signature,
    verify_rsa_signature,
)
from linotp.lib.support import PUB_KEY_LINOTP as LINOTP_PUB_KEY

TEST_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NGW3OnnZzQaFIVT9znr
VnWN2nA9rSdBxljy1ooZiPqb2yLiogs1KRDlU1WUVFBFZot2g3igkoKI11XbpvS+
ajgMg0hNnN7t26M3aB8ZgDYliVpzkZ++d8+EjvsUHfFaOtzXkgnqu6E4NYvonHc1
GkAVRkOLY7JN7hl1Ncd/3DGBefpPRw17zjR6hjN4vv9RECN6fdq0EobdOH+5sLw6
Z2OAB3oc8YpDRGB1DjjJ4b+PxENxG6r4I14XrpxNb+0nBmSuoUdRAOg/d+2mjKsI
yd1svJ/Qg5gVj1FcGr/DhetBJmLlUUhNnEjp27bSfXnF9V0KxyqNK35PxECRsxtt
xwIDAQAB
-----END PUBLIC KEY-----
"""

TEST_PRIV_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA0NGW3OnnZzQaFIVT9znrVnWN2nA9rSdBxljy1ooZiPqb2yLi
ogs1KRDlU1WUVFBFZot2g3igkoKI11XbpvS+ajgMg0hNnN7t26M3aB8ZgDYliVpz
kZ++d8+EjvsUHfFaOtzXkgnqu6E4NYvonHc1GkAVRkOLY7JN7hl1Ncd/3DGBefpP
Rw17zjR6hjN4vv9RECN6fdq0EobdOH+5sLw6Z2OAB3oc8YpDRGB1DjjJ4b+PxENx
G6r4I14XrpxNb+0nBmSuoUdRAOg/d+2mjKsIyd1svJ/Qg5gVj1FcGr/DhetBJmLl
UUhNnEjp27bSfXnF9V0KxyqNK35PxECRsxttxwIDAQABAoIBAGSFQBZAEsC/d/6A
4BaWrw8Dr7GDbm04BJWyo9Naz0f9O6GVfXt74a9PDtW60Jh1u7LNV9OZ8dIVPEJM
dlw8XJ1NNdjMqW/mcKHWRAm/TstFRXSFMjTbrRiHsMwTWW/AiyrivHL0iyafSSud
mfAYAlwMlTEpuqPXZWREpQOqcYZQ/9MxDsLhmBIN24KWqPNIdOViMWEm2S2bM6XN
KhRWgTiST8uPlgpNdZ0vnjDc/bvbWQkz61oPwZ9RAVC/fa5LZtW8HLpMiGlbOi6u
gl+LksZDIDYajVpyg8w5sTlnQYdPqu6ey7ZksXA9j4fly+o3jM/Hq3SKriX+ZXEp
PHr3bIECgYEA4XlkvFuvEsX/qMkYdL0iufAZLzmVFUjZxcWRgn1eZkPloocZoANG
LhzuL0XeZaLXL0WVJ0di5inFwZbxEChiuZuim6dBB2GDTajDcwf/5baUkKciIQy/
v4atSLic+MIu87EVqdWZ7SLiNY+qlvH5S7npvYesifU88QT/jA/ZgJcCgYEA7Rbw
5W3p9TDL1fy032DbMXNFaTLfUx+XNFQvjjWqlI9a3z0xYLWACLvFiJxYldXdAlxd
TMyg6WB/49MLjnGQ0ARDRXZlLJbko9QXyeoFQWBsSMcEMp7uroaZpRB3a4K2JlPC
EF5eLF7sVnKhUN660DANtoJW4NU7iDuMWEZ98lECgYAeEpfZ+4yFP31S4MdvQo6w
KBLj1pVIynepRimbMud1Ulb9b3F+gxFIMzmden8oJSj4OBqlq4LIWgfzQxOR6SEJ
ynVMt2kX9+yQXhL7c7SwycJU7MXDjLTCcc8I5P6iuxuSCytthHzMQRvUsv24tjte
20QOsFrV56yiJN2Eq9SBrwKBgCz8RFsT/udSCeshVuRniU+ZspriVzN7dAIu0xMl
pacoiDKBduQFrDR8BGAGYlyTxqqTAfT3grSlZb7BpZiyfaqqlGUSsOHEA7/+F0Ft
kO+1rvYkJOzB8UHWMkL6m94fYBZnoBPhA/dhT3CbsXYZvNKRu5hcpMVmUDRqMBfz
0CPxAoGATZKDdPwjPwJuUC2C+G6CuOhm06XHKjBDw3sjCe/uScgdX4ZvYynZmkzU
vJ+VFvLfYs5zNvb+N74E4y/FQPy6+UQA/36qFpF4aNdxYv+S0+2KwQ368R6CCCbQ
Ns0HoqfwxanoOmZIME0ESGZ+Ewu6JdMWDfoOadI6ZvcxgxbWrys=
-----END RSA PRIVATE KEY-----
"""


LINOTP_LICENSE = """
-----BEGIN LICENSE-----
comment=License for LSE LinOTP 2
contact-email=hs@unknown/unbekannt
licensee=Testkunde
expire=2020-05-22
contact-phone=unknown/unbekannt
address=unknown/unbekannt
date=2020-04-22
subscription=2021-04-22
token-num=5
contact-name=unknown/unbekannt
version=2
issuer=LSE Leading Security Experts GmbH
-----END LICENSE-----
-----BEGIN LICENSE SIGNATURE-----
ne4lEzFB25uORvWENH/3PIxxMDdkgNTlWxuOOQ+Pzz+oCrwtlWsLePZlbJB0DZRwt5b2I5ez9OFEkJ+YgkysTsUXYwmu/CcVtWVGtYPKR1hTuEoIVTuvEukkPKXLT7ioMPbFDjzsoTqVC4RK+JeEtT9upSaUVE6EkxJWjTnfTGuqx/jQTFHzDV7FXeUbs6C0h5rXoNYdrIFbSh3Z8JemVDPbPosBWiHTh/Tgyr3qG9ONJLG9R+jml4tZMQjI8iCEAEqUJF0Nv9ckCVz20a2ruCqPcG4SJ8WrcFWJoc61cXbRYuCmbh0Ku7Y1Shff61VaMMHRKTZbnUvJCduEDqcyJw==
-----END LICENSE SIGNATURE-----
"""


def parse_license(License):
    """parse a linotp license with a valid signature from linotp"""
    license_text = ""
    license_dict = {}
    license_mode = False

    signature = ""

    for line in License.strip().split("\n"):
        if line == "-----BEGIN LICENSE-----":
            license_mode = True
            continue

        if line == "-----BEGIN LICENSE SIGNATURE-----":
            license_mode = False
            continue

        if line in [
            "-----END LICENSE-----",
            "-----END LICENSE SIGNATURE-----",
        ]:
            continue

        if license_mode:
            license_text = license_text + line + "\n"

        if license_mode and "=" in line:
            key, _, value = line.partition("=")
            license_dict[key] = value

        if not license_mode:
            signature = signature + line

    return license_dict, license_text, signature


class TestRSA(unittest.TestCase):
    def test_rsa_cryto(self):
        """
        verify the signature of an expired linotp license
        """

        # ------------------------------------------------------------------ --

        # read the exired license and split it into message and signature

        _lic_dict, lic_msg, sig_msg = parse_license(LINOTP_LICENSE)

        message = lic_msg.encode("utf-8")
        signature = base64.b64decode(sig_msg)

        # ------------------------------------------------------------------ --

        # prepare the linotp pub key and run the tests

        public_key = LINOTP_PUB_KEY.strip().encode("utf-8")

        assert not verify_rsa_signature(public_key, message + b"x", signature)

        assert verify_rsa_signature(public_key, message, signature)

    def test_sign_and_verify(self):
        """
        verify the signing and verification step
        """

        rsa = RSA_Signature(
            private=TEST_PRIV_KEY.encode("utf-8"),
            public=TEST_PUB_KEY.encode("utf-8"),
        )

        message = b"hello world"

        signature = rsa.sign(message)

        assert rsa.verify(message, signature)

        assert not rsa.verify(message + b"x", signature)

        # try to reuse the verifyer

        assert rsa.verify(message, signature)

    def test_sign_and_verify_only_with_private_key(self):
        """
        verify the signing and verification step by only having an private key
        """

        rsa = RSA_Signature(
            private=TEST_PRIV_KEY.encode("utf-8"),
        )

        message = b"hello world"

        signature = rsa.sign(message)

        assert rsa.verify(message, signature)

        assert not rsa.verify(message + b"x", signature)

        # try to reuse the verifyer

        assert rsa.verify(message, signature)

    def test_sign_and_verify_simple(self):
        """
        verify the signing and verification step by only having an private key
        """

        message = b"hey do"
        private_key = TEST_PRIV_KEY.encode("utf-8")
        public_key = TEST_PUB_KEY.encode("utf-8")

        signature = create_rsa_signature(private_key, message)

        assert not verify_rsa_signature(public_key, message + b"x", signature)

        assert verify_rsa_signature(public_key, message, signature)


# eof
