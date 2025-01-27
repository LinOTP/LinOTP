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
  Test the U2F token
  To test the U2F token implementation, the behavior of a U2F device is simulated
  using a demo certificate and a hard-coded key handle
"""

import base64
import binascii
import json
import logging
import sys
from hashlib import sha256

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from linotp.tests import TestController

log = logging.getLogger(__name__)


def ECDSA_verify(cert, message, signature):
    """
    helper code to verify the created ECDSA signature - useful for development
    """

    cert = x509.load_der_x509_certificate(cert, default_backend())
    pubkey = cert.public_key()
    try:
        pubkey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as _exx:
        return False


def ECDSA_sign(private_key, message):
    """
    helper - create a ECDSA signature - useful for development
    """

    priv = serialization.load_pem_private_key(
        private_key, password=None, backend=default_backend()
    )

    return priv.sign(message, ec.ECDSA(hashes.SHA256()))


class TestU2FController(TestController):
    ATTESTATION_PRIVATE_KEY_PEM = (
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIBMsy03r5KbBIxkWY91FDJ7BvtTQhgPgndi282K4YrIOoAcGBSuBBAAK\n"
        "oUQDQgAE6WAdbosEirjc9p2R17WVNzz9hbITpR90OMf/sK+1ncXMiNt06oXF/0zw\n"
        "YnFZlka4GPRBhBtTWdgff+Ys/3JPKg==\n"
        "-----END EC PRIVATE KEY-----"
    )

    ATTESTATION_CERT_HEX = (
        "30820202308201a8a003020102020900bedc78032c47968b300a06082a8648ce3d0"
        "40302305f310b30090603550406130244453113301106035504080c0a536f6d652d"
        "53746174653121301f060355040a0c18496e7465726e65742057696467697473205"
        "07479204c74643118301606035504030c0f4c696e4f545020553246205465737430"
        "1e170d3135303331383039353230315a170d3432303830333039353230315a305f3"
        "10b30090603550406130244453113301106035504080c0a536f6d652d5374617465"
        "3121301f060355040a0c18496e7465726e6574205769646769747320507479204c7"
        "4643118301606035504030c0f4c696e4f5450205532462054657374305630100607"
        "2a8648ce3d020106052b8104000a03420004e9601d6e8b048ab8dcf69d91d7b5953"
        "73cfd85b213a51f7438c7ffb0afb59dc5cc88db74ea85c5ff4cf06271599646b818"
        "f441841b5359d81f7fe62cff724f2aa350304e301d0603551d0e04160414c17d9d5"
        "2e8f4696d4f485353fa78e903dab72aae301f0603551d23041830168014c17d9d52"
        "e8f4696d4f485353fa78e903dab72aae300c0603551d13040530030101ff300a060"
        "82a8648ce3d0403020348003045022007e475efd0c9575e915ab89b5c8b1b436b2c"
        "c9a5cc4df37889e9511b1f7808f6022100c1faaa0fa5f36363962058a2e9f679338"
        "eca18b12725f807ffe68d1c05d3d35b"
    )

    # Example key handle taken from the FIDO U2F specification
    KEY_HANDLE_HEX1 = (
        "2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551ba"
        "b61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25"
    )
    # Random made up key handle
    KEY_HANDLE_HEX2 = (
        "2ae0b2f28fae6053fd697972ba7c81009137f4f46a764bc29751a28987d053ccfffb0687d"
        "ef306f47fd45906e838401a6437270a45a37da9c25d8db8b559a888"
    )

    # Generate ECC key, NIST P-256 elliptic curve

    CURVE = ec.SECP256R1

    ECC_KEY1 = ec.generate_private_key(CURVE(), default_backend())
    ECC_KEY2 = ec.generate_private_key(CURVE(), default_backend())

    key_set = {1: (KEY_HANDLE_HEX1, ECC_KEY1), 2: (KEY_HANDLE_HEX2, ECC_KEY2)}

    key_handle_set = {
        KEY_HANDLE_HEX1: ECC_KEY1,
        KEY_HANDLE_HEX2: ECC_KEY2,
    }

    FAKE_REGISTRATION_DATA_HEX = (
        "0504113fafb0da1a6a90bb3a017552c1561af88bfd02c36eec334551959"
        "ffe562a6f050b496545810b64b738e7673a314efd67216cc1b7c7e46f1b"
        "34dcd6212a36fe402a552dfdb7477ed65fd84133f86196010b2215b57da"
        "75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe"
        "6660e2e006f76868b772d70c2530820202308201a8a003020102020900b"
        "edc78032c47968b300a06082a8648ce3d040302305f310b300906035504"
        "06130244453113301106035504080c0a536f6d652d53746174653121301"
        "f060355040a0c18496e7465726e6574205769646769747320507479204c"
        "74643118301606035504030c0f4c696e4f5450205532462054657374301"
        "e170d3135303331383039353230315a170d343230383033303935323031"
        "5a305f310b30090603550406130244453113301106035504080c0a536f6"
        "d652d53746174653121301f060355040a0c18496e7465726e6574205769"
        "646769747320507479204c74643118301606035504030c0f4c696e4f545"
        "02055324620546573743056301006072a8648ce3d020106052b8104000a"
        "03420004e9601d6e8b048ab8dcf69d91d7b595373cfd85b213a51f7438c"
        "7ffb0afb59dc5cc88db74ea85c5ff4cf06271599646b818f441841b5359"
        "d81f7fe62cff724f2aa350304e301d0603551d0e04160414c17d9d52e8f"
        "4696d4f485353fa78e903dab72aae301f0603551d23041830168014c17d"
        "9d52e8f4696d4f485353fa78e903dab72aae300c0603551d13040530030"
        "101ff300a06082a8648ce3d0403020348003045022007e475efd0c9575e"
        "915ab89b5c8b1b436b2cc9a5cc4df37889e9511b1f7808f6022100c1faa"
        "a0fa5f36363962058a2e9f679338eca18b12725f807ffe68d1c05d3d35b"
        "30440220387f2d2927e4a2bb9053b4ac09b22cc4c1bac2987e868be6f22"
        "6a8f139171838022013e19c68829d52b2e5db0e80e2efb46738cc418ea9"
        "ef3b94664f3817e18ddc4d"
    )

    # set up in setUp method
    serials = None

    def setUp(self):
        self.serial = ""
        self.counter = 0
        self.origin = "https://u2f-fakeurl.com"
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.serials = set()

    def tearDown(self):
        for serial in self.serials:
            self.delete_token(serial)
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def get_json_body(self, response):
        """
        Returns a JSON-decoded response body
        """
        return json.loads(response.body)

    def _registration1(self, pin=None):
        """
        Performs the first registration step
        """
        parameters = {
            "type": "u2f",
            "phase": "registration1",
            "user": "root",
            "session": self.session,
            "appid": self.origin,
        }
        if pin is not None:
            parameters["pin"] = pin

        response = self.make_admin_request("init", params=parameters)
        return response

    def _registration2(self, register_response_message, pin=None):
        """
        Performs the second registration step
        """
        parameters = {
            "type": "u2f",
            "phase": "registration2",
            "user": "root",
            "otpkey": register_response_message,
            "serial": self.serial,
            "session": self.session,
        }
        if pin is not None:
            parameters["pin"] = pin

        response = self.make_admin_request("init", params=parameters)
        return response

    def _authentication1(self, pin=None):
        """
        Performs the initial authentication step
        """
        parameters = {"user": "root", "pass": ""}
        if pin is not None:
            parameters["pass"] = pin

        response = self.make_validate_request("check", params=parameters)
        return response

    def _authentication2(
        self,
        transactionid,
        authentication_response_message,
        additional_params=None,
    ):
        """
        Performs the second authentication step
        """

        if additional_params is None:
            additional_params = {}

        parameters = {"user": "root", "transactionid": transactionid}

        parameters["pass"] = authentication_response_message

        parameters.update(additional_params)

        response = self.make_validate_request("check", params=parameters)

        return response

    def _createClientDataObject(self, typ, challenge):
        """
        Creates a client data object of the type 'registration' or 'authentication'
        """
        typ_string = ""
        if typ == "registration":
            typ_string = "navigator.id.finishEnrollment"
        elif typ == "authentication":
            typ_string = "navigator.id.getAssertion"
        else:
            raise ValueError("Unknown typ")

        client_data_object = {
            "typ": typ_string,
            "challenge": challenge,
            "origin": self.origin,
        }
        client_data_object_JSON = json.dumps(client_data_object)
        return client_data_object_JSON

    def _createRegistrationResponseMessage(
        self, client_data: str, key_set=None, correct=True
    ):
        """
        Create a registration response message according to the FIDO U2F specification
        """
        client_data = client_data.encode("utf-8")

        if not key_set:
            raise ValueError("Unknown key number requested!")
        (key_handle_hex, ecc_key) = key_set

        #
        # Create the registration_data object
        #
        registration_data = bytearray([5])  # First byte must be 0x05

        # ------------------------------------------------------------------ --

        # derive the public key in DER format from the private key
        #  the public key length is set to a fixed length of 65 characters
        #  in the U2F specification

        public_key = ecc_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )[-65:]

        registration_data += public_key

        key_handle = bytearray.fromhex(key_handle_hex)
        registration_data += len(key_handle).to_bytes(1, sys.byteorder)
        registration_data += key_handle

        attestation_cert_der = bytearray.fromhex(self.ATTESTATION_CERT_HEX)
        registration_data += attestation_cert_der

        # ------------------------------------------------------------------ --

        # Create the ECDSA signature:
        #  derive the signature from the message for appending

        private_key = self.ATTESTATION_PRIVATE_KEY_PEM.encode("ascii")

        message = (
            b"\x00"
            + sha256(self.origin.encode("utf-8")).digest()
            + sha256(client_data).digest()
            + key_handle
            + public_key
        )

        signature = ECDSA_sign(private_key, message)

        # ECDSA_verify(attestation_cert_der, message, signature)

        # ------------------------------------------------------------------ --

        # switch to change the signature to an invalid registration response
        # by cutting of the last byte

        if correct is False:
            signature = signature[:-1]

        registration_data += signature

        # ------------------------------------------------------------------ --

        # Create the registration_response
        #
        registration_response = {
            "registrationData": base64.urlsafe_b64encode(
                registration_data
            ).decode("ascii"),
            "clientData": base64.urlsafe_b64encode(client_data).decode(
                "ascii"
            ),
        }

        return json.dumps(registration_response)

    def _createAuthenticationResponseMessage(
        self, client_data: str, key_handle, ecc_key=None, correct=True
    ):
        """
        Create an authentication response message according to the FIDO U2F specification
        """
        # get the correct token for creating the response message
        if not ecc_key:
            raise ValueError("Unknown key handle received.")

        client_data = client_data.encode("utf-8")

        #
        # Create the signatureData object
        #
        authentication_data = bytearray([1])  # User presence byte

        # counter
        self.counter += 1
        authentication_data += self.counter.to_bytes(4, byteorder="big")

        # ------------------------------------------------------------------ --

        # create the dsa_asn1 signature

        message = (
            sha256(self.origin.encode("utf-8")).digest()
            + b"\x01"
            + self.counter.to_bytes(4, byteorder="big")
            + sha256(client_data).digest()
        )

        signature = ecc_key.sign(message, ec.ECDSA(hashes.SHA256()))

        # ------------------------------------------------------------------ --

        # switch to invalidate the signature by removing the last byte

        if correct is False:
            # Change the signature to create an invalid authentication response
            signature = signature[:-1]

        authentication_data += signature

        #
        # Create the signResponse object
        #
        # Remove trailing '=' characters
        key_handle = key_handle.rstrip(b"=")
        sign_response = {
            "keyHandle": key_handle.decode("ascii"),
            "signatureData": base64.urlsafe_b64encode(
                authentication_data
            ).decode("ascii"),
            "clientData": base64.urlsafe_b64encode(client_data).decode(
                "ascii"
            ),
        }

        return json.dumps(sign_response)

    def _registration(self, pin=None, correct=True, key_num=1):
        """
        Enroll a U2F token with given token pin
        """
        # Initial token registration step
        response_registration1 = self.get_json_body(self._registration1(pin))

        # check for status and value
        assert "result" in response_registration1, (
            "Response: %r" % response_registration1
        )
        assert "status" in response_registration1["result"], (
            "Response: %r" % response_registration1
        )
        assert response_registration1["result"]["status"]
        assert "value" in response_registration1["result"], (
            "Response: %r" % response_registration1
        )
        assert response_registration1["result"]["value"]

        # check detail object containing serial and registerrequest
        assert "detail" in response_registration1, (
            "Response: %r" % response_registration1
        )

        # check for correct serial
        assert "serial" in response_registration1["detail"], (
            "Response: %r" % response_registration1
        )
        assert response_registration1["detail"]["serial"][:3] == "U2F"

        # check for correct registerrequest object
        assert "registerrequest" in response_registration1["detail"], (
            "Response: %r" % response_registration1
        )
        assert (
            "challenge" in response_registration1["detail"]["registerrequest"]
        ), ("Response: %r" % response_registration1)
        # check for non-empty and correctly-padded challenge
        assert (
            response_registration1["detail"]["registerrequest"]["challenge"]
            != ""
        )
        assert (
            len(
                response_registration1["detail"]["registerrequest"][
                    "challenge"
                ]
            )
            % 4
            == 0
        )
        assert (
            "version" in response_registration1["detail"]["registerrequest"]
        ), ("Response: %r" % response_registration1)
        # only U2F_V2 is supported right now
        assert (
            response_registration1["detail"]["registerrequest"]["version"]
            == "U2F_V2"
        )
        assert (
            "appId" in response_registration1["detail"]["registerrequest"]
        ), ("Response: %r" % response_registration1)
        assert (
            response_registration1["detail"]["registerrequest"]["appId"]
            == self.origin
        )

        challenge_registration = response_registration1["detail"][
            "registerrequest"
        ]["challenge"]
        self.serial = response_registration1["detail"]["serial"]
        self.serials.add(self.serial)

        # Construct the registration response message
        client_data_registration = self._createClientDataObject(
            "registration",
            challenge_registration,
        )

        key_set = self.key_set.get(key_num, None)

        registration_response_message = (
            self._createRegistrationResponseMessage(
                client_data_registration, correct=correct, key_set=key_set
            )
        )

        # Complete the token registration
        response_registration2 = self.get_json_body(
            self._registration2(registration_response_message, pin)
        )

        # check for status and value
        assert "result" in response_registration2, (
            "Response: %r" % response_registration2
        )
        assert "status" in response_registration2["result"], (
            "Response: %r" % response_registration2
        )
        if correct:
            assert "value" in response_registration2["result"], (
                "Response: %r" % response_registration2
            )
            assert response_registration2["result"]["status"]
            assert response_registration2["result"]["value"]
        else:
            assert not response_registration2["result"]["status"]
            # check explicitly, that no "value: true" is responded
            if "value" in response_registration2["result"]:
                assert not response_registration2["result"]["value"]

        return

    def _authentication_challenge(self, pin=None):
        """
        Test authentication of a previously registered token with given token pin
        """
        # Initial authentication phase
        response_authentication1 = self.get_json_body(
            self._authentication1(pin)
        )

        # check for status and value
        assert "result" in response_authentication1, (
            "Response: %r" % response_authentication1
        )
        assert "status" in response_authentication1["result"], (
            "Response: %r" % response_authentication1
        )
        assert response_authentication1["result"]["status"]
        assert "value" in response_authentication1["result"], (
            "Response: %r" % response_authentication1
        )
        assert not response_authentication1["result"]["value"]

        assert "detail" in response_authentication1, (
            "Response: %r" % response_authentication1
        )

        # check for supported message
        assert "message" in response_authentication1["detail"], (
            "Response: %r" % response_authentication1
        )
        assert response_authentication1["detail"]["message"] in [
            "Multiple challenges submitted.",
            "U2F challenge",
        ]

        message = response_authentication1["detail"]["message"]

        reply = []
        if message == "Multiple challenges submitted.":
            assert "challenges" in response_authentication1["detail"], (
                "Response: %r" % response_authentication1
            )
            for challenge in list(
                response_authentication1["detail"]["challenges"].values()
            ):
                # check for non-empty transactionid
                assert "transactionid" in challenge, (
                    "Response: %r" % response_authentication1
                )
                assert challenge["transactionid"] != ""

                # check for correct signrequest object
                assert "signrequest" in challenge, (
                    "Response: %r" % response_authentication1
                )
                assert "challenge" in challenge["signrequest"], (
                    "Response: %r" % response_authentication1
                )
                # check for non-empty and correctly-padded challenge
                assert challenge["signrequest"]["challenge"] != ""
                assert len(challenge["signrequest"]["challenge"]) % 4 == 0
                assert "version" in challenge["signrequest"], (
                    "Response: %r" % response_authentication1
                )
                # only U2F_V2 is supported right now
                assert challenge["signrequest"]["version"] == "U2F_V2"
                assert "appId" in challenge["signrequest"], (
                    "Response: %r" % response_authentication1
                )
                assert challenge["signrequest"]["appId"] == self.origin

                # check for non-empty keyHandle
                assert "keyHandle" in challenge["signrequest"], (
                    "Response: %r" % response_authentication1
                )
                assert challenge["signrequest"]["keyHandle"] != ""

            challenges = response_authentication1["detail"]["challenges"]
            reply.extend(list(challenges.values()))
        else:
            # check for non-empty transactionid
            assert "transactionid" in response_authentication1["detail"], (
                "Response: %r" % response_authentication1
            )
            assert response_authentication1["detail"]["transactionid"] != ""

            # check for correct signrequest object
            assert "signrequest" in response_authentication1["detail"], (
                "Response: %r" % response_authentication1
            )
            assert (
                "challenge"
                in response_authentication1["detail"]["signrequest"]
            ), ("Response: %r" % response_authentication1)
            # check for non-empty and correctly-padded challenge
            assert (
                response_authentication1["detail"]["signrequest"]["challenge"]
                != ""
            )
            assert (
                len(
                    response_authentication1["detail"]["signrequest"][
                        "challenge"
                    ]
                )
                % 4
                == 0
            )
            assert (
                "version" in response_authentication1["detail"]["signrequest"]
            ), ("Response: %r" % response_authentication1)
            # only U2F_V2 is supported right now
            assert (
                response_authentication1["detail"]["signrequest"]["version"]
                == "U2F_V2"
            )
            assert (
                "appId" in response_authentication1["detail"]["signrequest"]
            ), ("Response: %r" % response_authentication1)
            assert (
                response_authentication1["detail"]["signrequest"]["appId"]
                == self.origin
            )

            # check for non-empty keyHandle
            assert (
                "keyHandle"
                in response_authentication1["detail"]["signrequest"]
            ), ("Response: %r" % response_authentication1)
            assert (
                response_authentication1["detail"]["signrequest"]["keyHandle"]
                != ""
            )
            reply.append(response_authentication1["detail"])
        return reply

    def _authentication_response(
        self, challenge, correct=True, additional_params=None
    ):
        if additional_params is None:
            additional_params = {}

        signrequest_authentication = challenge["signrequest"]
        challenge_authentication = signrequest_authentication["challenge"]

        # Does the received keyHandle match the sent one?
        key_handle_authentication = signrequest_authentication["keyHandle"]
        transactionid_authentication = challenge["transactionid"]
        # Correct the padding
        key_handle_authentication = key_handle_authentication + (
            "=" * (4 - (len(key_handle_authentication) % 4))
        )
        key_handle_authentication = key_handle_authentication.encode("ascii")
        assert binascii.hexlify(
            base64.urlsafe_b64decode(key_handle_authentication)
        ).decode("ascii") in [self.KEY_HANDLE_HEX1, self.KEY_HANDLE_HEX2], (
            "signrequest: %r" % signrequest_authentication
        )

        # Construct the registration response message
        client_data_authentication = self._createClientDataObject(
            "authentication",
            challenge_authentication,
        )

        key_handle_hex = binascii.hexlify(
            base64.urlsafe_b64decode(key_handle_authentication)
        ).decode("ascii")
        ecc_key = self.key_handle_set.get(key_handle_hex, None)

        authentication_response_message = (
            self._createAuthenticationResponseMessage(
                client_data_authentication,
                key_handle_authentication,
                ecc_key=ecc_key,
                correct=correct,
            )
        )
        # Complete the token authentication
        # breakpoint()
        response_authentication2 = self.get_json_body(
            self._authentication2(
                transactionid_authentication,
                authentication_response_message,
                additional_params,
            )
        )

        # check result object
        assert "result" in response_authentication2, (
            "Response: %r" % response_authentication2
        )
        assert "status" in response_authentication2["result"], (
            "Response: %r" % response_authentication2
        )
        assert response_authentication2["result"]["status"]
        assert "value" in response_authentication2["result"], (
            "Response: %r" % response_authentication2
        )
        if correct:
            assert response_authentication2["result"]["value"]
        else:
            assert not response_authentication2["result"]["value"]

        return response_authentication2

    def test_u2f_registration_and_authentication_without_pin(self):
        """
        Enroll a U2F token without a token pin and authenticate
        """

        self._registration()
        # Authenticate twice
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[0])
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[0])
        return

    def test_u2f_multiple_registration_and_authentication_without_pin(self):
        """
        Enroll a U2F token without a token pin and authenticate
        """

        self._registration(key_num=1)
        self._registration(key_num=2)

        # Try authenticating twice with each token
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[1])
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[1])
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[0])
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[0])
        return

    def test_u2f_registration_and_wrong_authentication_without_pin(self):
        """
        Enroll a U2F token without a token pin and perform an invalid authentication
        """

        self._registration()
        # Authenticate twice
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[0], correct=False)
        return

    def test_u2f_multiple_registration_and_wrong_authentication_without_pin(
        self,
    ):
        """
        Enroll a U2F token without a token pin and authenticate
        """

        self._registration(key_num=1)
        self._registration(key_num=2)

        # Try authenticating twice with each token
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[0], correct=False)
        challenges = self._authentication_challenge()
        self._authentication_response(challenges[1], correct=False)
        return

    def test_u2f_wrong_registration_without_pin(self):
        """
        Try an invalid registration of a U2F token without pin
        """

        self._registration(correct=False)

    def test_u2f_registration_and_authentication_with_pin(self):
        """
        Enroll a U2F token with a token pin and authenticate
        """

        pin = "test{pass}word_with{curly-braces{"
        self._registration(pin)
        # Authenticate twice
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0])
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0])
        return

    def test_u2f_multiple_registration_and_authentication_with_pin(self):
        """
        Enroll a U2F token without a token pin and authenticate
        """

        pin = "test{pass}word_with{curly-braces{"
        self._registration(pin=pin, key_num=1)
        self._registration(pin=pin, key_num=2)

        # Try authenticating twice with each token
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[1])
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[1])
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0])
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0])
        return

    def test_u2f_registration_and_wrong_authentication_with_pin(self):
        """
        Enroll a U2F token with a token pin and authenticate
        """

        pin = "test{pass}word_with{curly-braces{"
        self._registration(pin)
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0], correct=False)
        return

    def test_u2f_multiple_registration_and_wrong_authentication_with_pin(self):
        """
        Enroll a U2F token without a token pin and authenticate
        """

        pin = "test{pass}word_with{curly-braces{"
        self._registration(pin=pin, key_num=1)
        self._registration(pin=pin, key_num=2)

        # Try authenticating twice with each token
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0], correct=False)
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[1], correct=False)
        return

    def test_u2f_wrong_registration_with_pin(self):
        """
        Try an invalid registration of a U2F token with pin
        """

        pin = "test{pass}word_with{curly-braces{"
        self._registration(pin=pin, correct=False)

    def setOfflinePolicy(
        self,
        realm="*",
        name="u2f_offline",
        action="support_offline=u2f",
        active=True,
    ):
        params = {
            "name": name,
            "user": "*",
            "action": action,
            "scope": "authentication",
            "realm": realm,
            "time": "",
            "client": "",
            "active": active,
            "session": self.session,
        }

        response = self.make_system_request("setPolicy", params=params)
        assert '"status": true' in response, response

    def authentication_with_use_offline(self):
        """
        Tests, if info for U2F offline mode is transfered
        """

        pin = "test{pass}word_with{curly-braces{"
        self._registration(pin)
        # Authenticate twice
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0])
        challenges = self._authentication_challenge(pin)

        use_offline = {"use_offline": True}

        response = self._authentication_response(
            challenges[0], additional_params=use_offline
        )

        # policy is not set, so no offline info should be shown
        assert "detail" not in response

        # set the policy and check again
        self.setOfflinePolicy()

        # Authenticate twice
        challenges = self._authentication_challenge(pin)
        self._authentication_response(challenges[0])
        challenges = self._authentication_challenge(pin)

        use_offline = {"use_offline": True}

        response = self._authentication_response(
            challenges[0], additional_params=use_offline
        )

        assert "detail" in response
        detail = response.get("detail")

        assert "offline" in detail
        offline = detail.get("offline")

        assert "offline_info" in offline
        token_type = offline.get("token_type")
        assert "serial" in offline
        serial = offline.get("serial")

        assert serial == self.serial

        assert token_type == "u2f"

        assert "offline_info" in offline
        offline_info = offline.get("offline_info")

        # prepare info for comparison

        key_num = 1
        key_set = self.key_set.get(key_num, None)
        (key_handle_hex, ecc_key) = key_set
        key_handle_bin = binascii.unhexlify(key_handle_hex)
        key_handle_b64 = base64.urlsafe_b64encode(key_handle_bin)
        public_key = str(ecc_key.pub().get_der())[-65:]
        public_key_b64 = base64.urlsafe_b64encode(public_key)

        assert "key_handle" in offline_info
        key_handle_rec = offline_info.get("key_handle")
        assert key_handle_b64 == key_handle_rec

        assert "public_key" in offline_info
        public_key_rec = offline_info.get("public_key")
        assert public_key_b64 == public_key_rec

        assert "app_id" in offline_info
        app_id = offline_info.get("app_id")
        assert app_id == self.origin

        assert "counter" in offline_info
        counter = offline_info.get("counter")
        assert counter == self.counter
