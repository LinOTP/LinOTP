"""
SoftWebauthnDevice — A pure-software FIDO2/WebAuthn authenticator for tests.

Generates real ES256 key pairs, produces valid attestation and assertion
responses that pass ``Fido2Server.register_complete`` and
``Fido2Server.authenticate_complete`` without any mocking or patching.

Usage::

    from linotp.tests.functional.fido2_device import SoftWebauthnDevice

    device = SoftWebauthnDevice()

    # Registration
    attestation_response = device.create(creation_options, origin)

    # Authentication
    assertion_response = device.get(request_options, origin)

Inspired by the test patterns in
https://github.com/Yubico/python-fido2/tree/main/tests
"""

import hashlib
import json
import os
import struct
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from fido2 import cbor
from fido2.utils import websafe_encode

# AAGUID for our virtual authenticator (arbitrary fixed UUID)
_AAGUID = UUID("f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0")

DEFAULT_ORIGIN = "https://localhost"


class SoftWebauthnDevice:
    """A software FIDO2 authenticator that creates real cryptographic
    credentials and signs assertions — no mocking required."""

    def __init__(self):
        self.credential_id: bytes | None = None
        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.sign_count: int = 0
        self.aaguid: bytes = _AAGUID.bytes
        self.rp_id: str | None = None

    # ------------------------------------------------------------------
    # Registration  (navigator.credentials.create)
    # ------------------------------------------------------------------

    def create(self, creation_options: dict, origin=DEFAULT_ORIGIN) -> dict:
        """Simulate ``navigator.credentials.create()``.

        :param creation_options: The ``publicKey`` member of the
            ``PublicKeyCredentialCreationOptions`` returned by
            ``Fido2Server.register_begin``.  When the server returns
            ``{"publicKey": {…}}``, pass the inner dict.
        :param origin: The RP origin, e.g. ``"https://localhost"``
            or ``"http://localhost"`` for tests.
        :return: A dict in the shape expected by
            ``Fido2Server.register_complete``.
        """
        # Extract RP ID from the creation options
        rp = creation_options.get("rp", {})
        self.rp_id = rp.get("id", "localhost")
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()

        # Extract challenge (base64url-encoded string)
        challenge = creation_options["challenge"]

        # Generate a new credential
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

        # Build COSE key (ES256 = algorithm -7)
        public_key = self.private_key.public_key()
        public_numbers = public_key.public_numbers()
        cose_key = {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }

        # Build AttestedCredentialData
        # https://www.w3.org/TR/webauthn-2/#attested-credential-data
        cred_id_len = len(self.credential_id)
        attested_cred_data = (
            self.aaguid  # 16 bytes
            + struct.pack(">H", cred_id_len)  # 2 bytes
            + self.credential_id  # cred_id_len bytes
            + cbor.encode(cose_key)  # CBOR-encoded public key
        )

        # Build AuthenticatorData
        # https://www.w3.org/TR/webauthn-2/#authenticator-data
        flags = 0x41  # UP (user present) + AT (attested credential data)
        auth_data = (
            rp_id_hash  # 32 bytes
            + struct.pack(">B", flags)  # 1 byte
            + struct.pack(">I", self.sign_count)  # 4 bytes  (counter)
            + attested_cred_data
        )

        # Build AttestationObject (CBOR) with "none" attestation
        attestation_object = cbor.encode(
            {
                "fmt": "none",
                "attStmt": {},
                "authData": auth_data,
            }
        )

        # Build CollectedClientData
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()

        # Return the response in the standard WebAuthn shape
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client_data),
                "attestationObject": websafe_encode(attestation_object),
            },
        }

    # ------------------------------------------------------------------
    # Authentication  (navigator.credentials.get)
    # ------------------------------------------------------------------

    def get(self, request_options: dict, origin=DEFAULT_ORIGIN) -> dict:
        """Simulate ``navigator.credentials.get()``.

        :param request_options: The ``publicKey`` member of the
            ``PublicKeyCredentialRequestOptions`` returned by
            ``Fido2Server.authenticate_begin``.  When the server returns
            ``{"publicKey": {…}}``, pass the inner dict.
        :param origin: The RP origin.
        :return: A dict in the shape expected by
            ``Fido2Server.authenticate_complete``.
        """
        if self.private_key is None or self.credential_id is None:
            msg = "No credential — call create() first"
            raise RuntimeError(msg)

        rp_id = self.rp_id or "localhost"
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        challenge = request_options["challenge"]

        self.sign_count += 1

        # Build AuthenticatorData (no attested credential data for assertion)
        flags = 0x01  # UP (user present)
        auth_data = (
            rp_id_hash + struct.pack(">B", flags) + struct.pack(">I", self.sign_count)
        )

        # Build CollectedClientData
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()

        client_data_hash = hashlib.sha256(client_data).digest()

        # Sign (authenticatorData || clientDataHash)
        signature = self.private_key.sign(
            auth_data + client_data_hash,
            ec.ECDSA(SHA256()),
        )

        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client_data),
                "authenticatorData": websafe_encode(auth_data),
                "signature": websafe_encode(signature),
            },
        }
