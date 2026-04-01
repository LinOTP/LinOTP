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
FIDO2/WebAuthn Token Implementation

This file contains the FIDO2 token class implementing the WebAuthn protocol
for two-factor authentication using hardware security keys (e.g. YubiKey 5,
SoloKeys, platform authenticators).

The FIDO2 protocol involves two ceremonies:

    - **Registration (attestation)**: The user registers a FIDO2 authenticator
        with LinOTP. The authenticator generates a new key pair and sends the
        public key to the server.

    - **Authentication (assertion)**: The user signs a server-generated challenge
        with the authenticator's private key. The server verifies the signature
        using the stored public key.


Enrollment is a two-phase process via /userservice:

    Phase 1 (via /userservice/enroll, tokenType=fido2):
        - The client sends a request with parameters:
            - ``type``: "fido2"
            - ``description``: (optional)
            - ``session``: session identifier
        - The server responds with:
            - ``result.status``: true/false (server status; false indicates a request or server error)
            - ``result.value``: true/false (registration success)
            - ``detail.serial``: token serial
            - ``detail.registerrequest``: ``PublicKeyCredentialCreationOptions`` (WebAuthn registration challenge)
        - The client uses the ``registerrequest`` with the authenticator (e.g., security key or platform authenticator)
          via the browser's WebAuthn API (``navigator.credentials.create``) to generate an attestation response.

    Phase 2 (via /userservice/fido2_activate_finish):
        - The client sends a request with parameters:
            - ``serial``: token serial
            - ``session``: session identifier
            - ``attestationResponse``: WebAuthn attestation response (JSON)
        - The server verifies the attestation and, if successful, stores the credential and activates the token.
        - The server responds with:
            - ``result.status``: true/false (server status; false indicates a request or server error)
            - ``result.value``: true/false (registration success)
            - ``detail.serial``: token serial
            - ``result.error``: (optional) error details

    Users can also retrigger the challenge via ``/userservice/fido2_activate_begin`` to obtain a new registration challenge if needed.



Authentication is a two-step challenge-response process:

    Step 1: Client triggers a challenge via ``/validate/check`` by sending:
        - ``user``: Username
        - ``pass``: PIN (optional, if required)
        - ``realm``: (optional)

        The server responds with:
        - ``result.status``: true/false (server status; false indicates a request or server error)
        - ``result.value``: true/false (challenge trigger success)
        - ``detail.challenges``: Map of FIDO2 token serials to challenge objects
        - Each challenge object contains:
            - ``signrequest``: ``PublicKeyCredentialRequestOptions`` (for WebAuthn)
            - ``transactionid``: Transaction ID for this challenge
            - ``linotp_tokenserial``: Token serial (unique identifier for the token)
            - ``linotp_tokentype``: Token type (should be 'fido2')
            - ``linotp_tokendescription``: (optional)

    Step 2: The client uses the ``signrequest`` with the authenticator (e.g., security key or platform authenticator)
            to generate a WebAuthn assertion response locally (via the browser's WebAuthn API).
            The client then sends this assertion response to the server via ``/validate/check_t`` by sending:
            - ``transactionid``: Transaction ID from the challenge
            - ``pass``: The stringified WebAuthn assertion response

        The assertion response must be a JSON string in the following format:
            {
                id: string (credential ID)
                rawId: string (base64url-encoded credential ID)
                type: string ('public-key')
                response: {
                    clientDataJSON: string (base64url)
                    authenticatorData: string (base64url)
                    signature: string (base64url)
                    userHandle: string (optional, base64url)
                }
            }

        The server verifies the assertion and responds with:
        - ``result.status``: true/false (server status; false indicates a request or server error)
        - ``result.value``: true/false or nested object with ``value: true`` for authentication success
        - ``result.error``: (optional) error details
        - ``result.poll``: (optional) true if polling is required
"""

import base64
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from fido2.cbor import decode as cbor_decode
from fido2.cbor import encode as cbor_encode
from fido2.cose import CoseKey
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorAttachment,
    AuthenticatorData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from flask import g
from flask_babel import gettext as _

from linotp.lib.auth.validate import check_pin
from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError, TokenAdminError
from linotp.lib.policy import get_client_policy, get_tokenlabel
from linotp.lib.policy.action import get_action_value
from linotp.lib.user import User
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import TokenClass

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------- --
# Constants
# ---------------------------------------------------------------------- --

# Token type and prefix for FIDO2 tokens
FIDO2_TOKEN_TYPE = "fido2"
FIDO2_TOKEN_PREFIX = "FIDO2"

# TokenInfo keys
TOKEN_INFO_PHASE = "phase"
TOKEN_INFO_REGISTRATION_CHALLENGE = "registration_challenge"
TOKEN_INFO_RP_ID = "rp_id"
TOKEN_INFO_RP_NAME = "rp_name"
TOKEN_INFO_COUNTER = "counter"
TOKEN_INFO_CREDENTIAL = "fido2_credential"
TOKEN_INFO_ATTESTATION_CONVEYANCE = "attestation_conveyance"
TOKEN_INFO_LAST_AUTH = "last_auth_at"
TOKEN_INFO_LAST_AUTH_UV = "last_auth_uv"

# Policy action keys
POLICY_RP_ID = "fido2_rp_id"
POLICY_RP_NAME = "fido2_rp_name"
POLICY_TOKENISSUER = "tokenissuer"  # legacy equivalent for fido2_rp_name
POLICY_ATTESTATION = "fido2_attestation_conveyance"
POLICY_USER_VERIFICATION = "fido2_user_verification_requirement"
POLICY_RESIDENT_KEY = "fido2_resident_key_requirement"
POLICY_AUTHENTICATOR_TYPES = "fido2_authenticator_types"

ATTESTATION_PREFERENCE_MAP = {
    "direct": AttestationConveyancePreference.DIRECT,
    "indirect": AttestationConveyancePreference.INDIRECT,
    "none": AttestationConveyancePreference.NONE,
    "enterprise": AttestationConveyancePreference.ENTERPRISE,
}

USER_VERIFICATION_MAP = {
    "required": UserVerificationRequirement.REQUIRED,
    "preferred": UserVerificationRequirement.PREFERRED,
    "discouraged": UserVerificationRequirement.DISCOURAGED,
}

RESIDENT_KEY_MAP = {
    "required": ResidentKeyRequirement.REQUIRED,
    "preferred": ResidentKeyRequirement.PREFERRED,
    "discouraged": ResidentKeyRequirement.DISCOURAGED,
}

DEFAULT_ATTESTATION = ATTESTATION_PREFERENCE_MAP["direct"]
DEFAULT_RESIDENT_KEY = RESIDENT_KEY_MAP["preferred"]
DEFAULT_USER_VERIFICATION = USER_VERIFICATION_MAP["preferred"]

# Conveyance preferences that require actual attestation data
ATTESTATION_REQUIRED_PREFERENCES = {
    AttestationConveyancePreference.DIRECT,
    AttestationConveyancePreference.INDIRECT,
    AttestationConveyancePreference.ENTERPRISE,
}


# WebAuthn hints (Level 3) corresponding to preferred types
HINT_CLIENT_DEVICE = "client-device"
HINT_SECURITY_KEY = "security-key"
HINT_HYBRID = "hybrid"

VALID_AUTHENTICATOR_TYPES = {HINT_CLIENT_DEVICE, HINT_SECURITY_KEY, HINT_HYBRID}

RP_NAME_DEFAULT = "LinOTP"


def compute_authenticator_types_options(
    authenticator_types: list[str],
) -> dict:
    """Compute authenticator_attachment and hints from authenticator types.

    :param authenticator_types: list of authenticator type strings
        ("client-device", "security-key", "hybrid"); order is preserved
    :return: dict with optional keys "authenticator_attachment" and "hints"
    """

    # keep only valid types, preserving the order from the policy
    types = [t for t in authenticator_types if t in VALID_AUTHENTICATOR_TYPES]
    if not types:
        return {}

    hints = types
    types_set = set(types)
    has_client_device = HINT_CLIENT_DEVICE in types_set
    has_cross_platform = HINT_SECURITY_KEY in types_set or HINT_HYBRID in types_set

    result: dict = {"hints": hints}

    if has_client_device and not has_cross_platform:
        result["authenticator_attachment"] = AuthenticatorAttachment.PLATFORM
    elif has_cross_platform and not has_client_device:
        result["authenticator_attachment"] = AuthenticatorAttachment.CROSS_PLATFORM
    # else: both present → don't restrict attachment

    return result


# ---------------------------------------------------------------------- --
# Policy helper functions
# ---------------------------------------------------------------------- --


def _get_enrollment_policy_action(action: str, user) -> str:
    """Retrieve the value of an enrollment policy action for the given user.

    :param action: policy action name
    :param user: user object with login and realm attributes
    :return: policy value as string, or empty string if not found
    """
    if not (
        policies := get_client_policy(
            context["Client"],
            scope="enrollment",
            user=user.login,
            realm=user.realm,
            action=action,
        )
    ):
        return ""

    return get_action_value(
        policies,
        scope="enrollment",
        action=action,
        default="",
    )


def _resolve_enrollment_policy(action: str, user=None) -> str | None:
    """Look up an enrollment policy action for the given user.

    :param action: policy action name (e.g. ``POLICY_ATTESTATION``)
    :param user: user object with ``login`` and ``realm``
    :return: lowercased policy value, or ``None`` when the user is
        missing or the policy is not set
    """
    if not user or not user.login or not user.realm:
        log.debug("_resolve_enrollment_policy(%s): user info missing", action)
        return None

    policy_value = _get_enrollment_policy_action(action, user)
    if policy_value:
        if isinstance(policy_value, str):
            return policy_value.lower()
        else:
            return policy_value
    return None


class TokenPhase(str, Enum):
    """Token lifecycle phases."""

    REGISTRATION = "registration"
    AUTHENTICATION = "authentication"


# ---------------------------------------------------------------------- --
# Data Classes for FIDO2 Structures
# ---------------------------------------------------------------------- --


@dataclass
class Fido2Credential:
    """Stored FIDO2 credential data.

    Fields:
        credential_id        - base64url-encoded credential ID
        public_key           - base64url-encoded CBOR public key
        sign_count           - Current signature counter
        rp_id                - Relying Party ID this credential is bound to
        aaguid               - Authenticator model identifier (UUID string)
        attestation_format   - Attestation format ("packed", "none", etc.)
        public_key_algorithm - COSE algorithm ID (-7 = ES256, -257 = RS256, etc.)
        auth_data_flags      - Raw authenticator data flags byte from registration
        backup_eligible      - BE flag: credential can be backed up (passkey)
        backed_up            - BS flag: credential IS backed up (synced passkey)
        user_verified_at_reg - UV flag was set during registration
        attestation_cert_b64 - Base64-encoded DER attestation certificate, or
                               None if the authenticator did not provide one
        registered_at        - ISO 8601 timestamp of registration
    """

    credential_id: str  # base64url-encoded credential ID
    public_key: str  # base64url-encoded CBOR public key
    sign_count: int  # Current signature counter
    rp_id: str  # Relying Party ID this credential is bound to
    aaguid: str  # UUID string, e.g. "cb69481e-8ff7-4039-93ec-..."
    attestation_format: str  # "packed", "none", "tpm", etc.
    public_key_algorithm: int  # COSE alg ID: -7, -257, -8, etc.
    auth_data_flags: int  # Raw flags byte from registration
    backup_eligible: bool  # BE flag
    backed_up: bool  # BS flag
    user_verified_at_reg: bool  # UV flag at registration
    attestation_cert_b64: str | None  # Base64 DER certificate (None if not provided)
    registered_at: str  # ISO 8601 timestamp

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {
            "credential_id": self.credential_id,
            "public_key": self.public_key,
            "sign_count": self.sign_count,
            "rp_id": self.rp_id,
            "aaguid": self.aaguid,
            "attestation_format": self.attestation_format,
            "public_key_algorithm": self.public_key_algorithm,
            "auth_data_flags": self.auth_data_flags,
            "backup_eligible": self.backup_eligible,
            "backed_up": self.backed_up,
            "user_verified_at_reg": self.user_verified_at_reg,
            "attestation_cert_b64": self.attestation_cert_b64,
            "registered_at": self.registered_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Fido2Credential":
        """Create from dictionary loaded from JSON."""
        return cls(
            credential_id=data["credential_id"],
            public_key=data["public_key"],
            sign_count=data["sign_count"],
            rp_id=data["rp_id"],
            aaguid=data["aaguid"],
            attestation_format=data["attestation_format"],
            public_key_algorithm=data["public_key_algorithm"],
            auth_data_flags=data["auth_data_flags"],
            backup_eligible=data["backup_eligible"],
            backed_up=data["backed_up"],
            user_verified_at_reg=data["user_verified_at_reg"],
            attestation_cert_b64=data["attestation_cert_b64"],
            registered_at=data["registered_at"],
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Fido2Credential":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def to_json(self) -> str:
        """Convert to JSON string for storage."""
        return json.dumps(self.to_dict())


@tokenclass_registry.class_entry(FIDO2_TOKEN_TYPE)
@tokenclass_registry.class_entry("linotp.tokens.fido2token.fido2token.Fido2TokenClass")
class Fido2TokenClass(TokenClass):
    """
    FIDO2/WebAuthn token class implementation.

    The FIDO2 protocol as specified by the W3C WebAuthn standard uses
    public key cryptography to perform second factor authentications.
    On registration, the FIDO2 authenticator creates a public/private
    key pair and sends the public key to the relying party (this LinOTP
    class). On authentication, the authenticator uses the private key
    to sign a challenge received from the relying party. This signature
    can be verified using the public key stored during registration.
    """

    def __init__(self, aToken):
        """
        Constructor - create a token object.

        :param aToken: instance of the ORM db object
        :type aToken: orm object
        """
        super().__init__(aToken)
        self.setType(FIDO2_TOKEN_TYPE)
        self.mode = ["challenge"]  # This is a challenge-response token
        self.supports_offline_mode = False
        self.hKeyRequired = False  # FIDO2 uses public key, not OTP key

    @classmethod
    def getClassType(cls):
        return FIDO2_TOKEN_TYPE

    @classmethod
    def getClassPrefix(cls):
        return FIDO2_TOKEN_PREFIX

    @classmethod
    def getClassInfo(cls, key=None, ret="all"):
        """
        Return a subtree of the token definition.

        :param key: subsection identifier
        :type key: string
        :param ret: default return value, if nothing is found
        :type ret: user defined
        :return: subsection if key exists or user defined
        :rtype: dict
        """
        res = {
            "type": FIDO2_TOKEN_TYPE,
            "title": "FIDO2 WebAuthn Token",
            "description": (
                "A FIDO2/WebAuthn token for passwordless or second-factor "
                "authentication using hardware security keys or platform "
                "authenticators. Can be combined with the OTP PIN."
            ),
            "selfservice": {
                "enroll": {}  # keep for dynamic policy definitions
            },
            "init": {
                "title": {
                    "html": "fido2token/fido2token.mako",
                    "scope": "enroll.title",
                },
                "page": {
                    "html": "fido2token/fido2token.mako",
                    "scope": "enroll",
                },
            },
            "config": {
                "title": {
                    "html": "fido2token/fido2token.mako",
                    "scope": "config.title",
                },
                "page": {
                    "html": "fido2token/fido2token.mako",
                    "scope": "config",
                },
            },
            "policy": {
                "enrollment": {
                    POLICY_RP_ID: {
                        "type": "str",
                        "desc": _("Relying Party ID for FIDO2/WebAuthn tokens"),
                    },
                    POLICY_RP_NAME: {
                        "type": "str",
                        "desc": _("Relying Party name for FIDO2/WebAuthn tokens"),
                    },
                    POLICY_ATTESTATION: {
                        "type": "set",
                        "value": ["direct", "indirect", "none", "enterprise"],
                        "desc": _(
                            "Attestation conveyance preference for FIDO2/WebAuthn "
                            "token enrollment. Controls whether and how the "
                            "authenticator's attestation statement is conveyed "
                            "during registration."
                        ),
                    },
                    POLICY_USER_VERIFICATION: {
                        "type": "set",
                        "value": ["required", "preferred", "discouraged"],
                        "desc": _(
                            "User verification requirement for FIDO2/WebAuthn "
                            "tokens. Controls whether the authenticator must "
                            "verify the user (e.g. via PIN or biometric) during "
                            "registration and authentication."
                        ),
                    },
                    POLICY_RESIDENT_KEY: {
                        "type": "set",
                        "value": ["required", "preferred", "discouraged"],
                        "desc": _(
                            "Resident key (discoverable credential) requirement preference "
                            "for FIDO2/WebAuthn token enrollment. Controls "
                            "whether the authenticator should create a "
                            "discoverable credential."
                        ),
                    },
                    POLICY_AUTHENTICATOR_TYPES: {
                        "type": "set",
                        "range": ["client-device", "security-key", "hybrid"],
                        "desc": _(
                            "Preferred authenticator types for FIDO2/WebAuthn "
                            "token enrollment. Controls authenticator attachment "
                            "and WebAuthn hints sent to the client."
                        ),
                    },
                },
            },
        }

        if key is not None and key in res:
            ret = res.get(key)
        elif ret == "all":
            ret = res
        return ret

    # ---------------------------------------------------------------------- --
    # Helper methods
    # ---------------------------------------------------------------------- --

    def _get_fido2_server(
        self,
        attestation: AttestationConveyancePreference = DEFAULT_ATTESTATION,
    ) -> Fido2Server:
        """Return a :class:`Fido2Server` configured for the RP associated
        with the token.

        :param attestation: Attestation conveyance preference. Defaults to
            DIRECT. During enrollment, the value is determined by the
            ``fido2_attestation_conveyance`` enrollment policy.
        """

        rp_id: str = self.getFromTokenInfo(TOKEN_INFO_RP_ID)
        rp_name: str = self.getFromTokenInfo(TOKEN_INFO_RP_NAME)

        # we dont check origin for now
        server = Fido2Server(
            rp=PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
            attestation=attestation,
        )
        server.timeout = self.get_challenge_validity()
        return server

    def _get_stored_credential(self) -> Fido2Credential:
        """
        Retrieve stored credential data from token info.

        :return: Fido2Credential object
        :raises ValueError: if no credential is stored or if JSON is invalid
        """
        cred_json = self.getFromTokenInfo(TOKEN_INFO_CREDENTIAL, None)
        if not cred_json:
            msg = f"No FIDO2 credential stored for token {self.getSerial()}"
            raise ValueError(msg)

        return Fido2Credential.from_json(cred_json)

    @staticmethod
    def _parse_challenge_data(challenge: dict):
        """Extract the saved challenge data from a challenge dict."""
        data = challenge.get("data")
        if not data:
            return None
        if isinstance(data, str):
            data: dict = json.loads(data)
        return data.get("challenge")

    # ---------------------------------------------------------------------- --
    # Helper methods for state conversion
    # ---------------------------------------------------------------------- --

    @staticmethod
    def _serialize_state(state: dict) -> str:
        """
        Serialize Fido2Server state to JSON with enum handling.

        :param state: state dict from Fido2Server (may contain enums)
        :return: JSON string representation
        """
        return json.dumps(state, default=str)

    @staticmethod
    def _deserialize_state(state_json: str) -> dict:
        """
        Deserialize Fido2Server state from JSON and restore enums.

        :param state_json: JSON string representation of state
        :return: state dict with UserVerificationRequirement enum restored
        :raises ParameterError: on invalid JSON or enum values
        """
        try:
            state = json.loads(state_json)
            # Restore UserVerificationRequirement enum if present
            if "user_verification" in state and state["user_verification"] is not None:
                state["user_verification"] = UserVerificationRequirement(
                    state["user_verification"]
                )
            return state
        except (ValueError, TypeError, KeyError) as exx:
            msg = "Invalid or corrupted registration/challenge state"
            raise ParameterError(msg) from exx

    def _reconstruct_attested_credential(self) -> AttestedCredentialData:
        """
        Reconstruct AttestedCredentialData from stored credential for verification.

        :return: AttestedCredentialData object
        :raises ParameterError: if credential cannot be reconstructed
        """
        cred = self._get_stored_credential()

        try:
            # Decode stored credential data
            credential_id = websafe_decode(cred.credential_id)
            public_key_cbor = websafe_decode(cred.public_key)
            public_key_map = cbor_decode(public_key_cbor)
            cose_key = CoseKey.parse(public_key_map)

            # Convert AAGUID string back to bytes
            aaguid_uuid = UUID(cred.aaguid)
            aaguid_bytes = aaguid_uuid.bytes

            # Reconstruct AttestedCredentialData
            return AttestedCredentialData.create(
                aaguid=aaguid_bytes,
                credential_id=credential_id,
                public_key=cose_key,
            )
        except (ValueError, AttributeError, TypeError) as exx:
            msg = f"Failed to reconstruct FIDO2 credential: {exx}"
            raise ParameterError(msg) from exx

    # ---------------------------------------------------------------------- --
    # Enrollment (Registration) phases
    # ---------------------------------------------------------------------- --

    def update(self, param, reset_failcount=False):
        """
        Handle token enrollment.

        Two-phase process:
          Phase 1: Token is created, registration challenge will be generated in getInitDetail.
          Phase 2: attestationResponse from the authenticator is verified and credential stored.

        :param param: request parameters
        :type param: dict
        """
        self.setSyncWindow(0)
        self.setOtpLen(32)
        self.setCounterWindow(0)

        tdesc = param.get("description")
        if tdesc is not None:
            self.token.setDescription(tdesc)

        # Detect phase by presence of attestationResponse
        is_phase2 = param.get("attestationResponse") is not None
        current_phase = self.getFromTokenInfo(TOKEN_INFO_PHASE, None)

        if is_phase2:
            # Phase 2: Complete registration with attestation response
            if current_phase != TokenPhase.REGISTRATION:
                msg = "Attestation response received but token is not in registration state."
                raise ParameterError(msg)
            # Verify attestation and complete registration
            # (PIN is validated during authentication, not enrollment)
        # Phase 1: Initialize or regenerate challenge
        elif current_phase is None:
            # Initialize new token
            pin = param.get("pin")
            if pin is not None:
                TokenClass.setPin(self, pin)
            self.addToTokenInfo(TOKEN_INFO_PHASE, TokenPhase.REGISTRATION)
            self.token.LinOtpIsactive = False
        elif current_phase == TokenPhase.REGISTRATION:
            # Allow regeneration of challenge
            # (e.g. if user failed to complete registration and needs a new challenge)
            pass
        else:
            msg = f"Token is in an invalid state for initialization! Current phase: {current_phase}"
            raise ParameterError(msg)

    def getInitDetail(self, params, user=None):
        """
        Build the response for token initialization.

        Phase 1 returns a ``publicKeyCredentialCreationOptions`` object.
        Phase 2 verifies the attestation response and stores the credential.

        :param params: request parameters
        :param user: the user the token is assigned to
        :return: dict with response details
        """
        response_detail = {}

        info = self.getInfo()
        response_detail.update(info)
        response_detail["serial"] = self.getSerial()

        # Detect phase by presence of attestationResponse parameter
        if params.get("attestationResponse") is not None:
            params["otpkey"] = params.pop("attestationResponse")
            response_detail.update(self._handle_registration_phase2(params, user))
        else:
            response_detail.update(self._handle_registration_phase1(params, user))

        return response_detail

    def _get_rp_id_and_name_from_policies(self, user=None) -> dict[str, str]:
        """Obtain RP ID and RP name from appropriate policies. Returns
        a dictionary with `rp_id` and `rp_name` items, or an empty
        dictionary if no RP ID could be located in policies.
        """

        # The user stuff will also have been checked in the method
        # `_handle_registration_phase1()` below.  We check it again
        # here for safety, in case this method is ever called from
        # elsewhere.

        if not user or not user.login or not user.realm:
            log.debug("_get_rp_id_and_name_from_policies: user info missing")
            return {}

        # Have to have an RP ID somehow.

        if not (rp_id := _get_enrollment_policy_action(POLICY_RP_ID, user)):
            log.debug(
                "_get_rp_id_and_name_from_policies: no `%s=` policy found", POLICY_RP_ID
            )
            return {}

        # We support `tokenissuer=` as a legacy equivalent to `fido2_rp_name=`,
        # if `fido2_rp_name=` is not defined.

        for action in (POLICY_RP_NAME, POLICY_TOKENISSUER):
            if rp_name := _get_enrollment_policy_action(action, user):
                break
        else:
            rp_name = RP_NAME_DEFAULT

        result = {"rp_id": rp_id, "rp_name": rp_name}
        log.debug("_get_rp_id_and_name_from_policies: result=%r", result)
        return result

    def _get_attestation_preference(self, user=None) -> AttestationConveyancePreference:
        """Determine the attestation conveyance preference from the enrollment policy.

        :param user: user object
        :return: AttestationConveyancePreference enum value
        """
        value = _resolve_enrollment_policy(POLICY_ATTESTATION, user)
        return ATTESTATION_PREFERENCE_MAP.get(value, DEFAULT_ATTESTATION)

    def _get_user_verification_requirement(
        self, user=None
    ) -> UserVerificationRequirement:
        """Determine the user verification requirement from the enrollment policy.

        :param user: user object
        :return: UserVerificationRequirement enum value
        """
        value = _resolve_enrollment_policy(POLICY_USER_VERIFICATION, user)
        return USER_VERIFICATION_MAP.get(value, DEFAULT_USER_VERIFICATION)

    def _get_resident_key_requirement(self, user=None) -> ResidentKeyRequirement:
        """Determine the resident key requirement from the enrollment policy.

        :param user: user object
        :return: ResidentKeyRequirement enum value
        """
        value = _resolve_enrollment_policy(POLICY_RESIDENT_KEY, user)
        return RESIDENT_KEY_MAP.get(value, DEFAULT_RESIDENT_KEY)

    def _get_authenticator_types(self, user=None) -> list[str]:
        """Retrieve the ``fido2_authenticator_types`` enrollment policy value.

        :param user: user object
        :return: list of valid preferred type strings (order preserved from policy)
        """
        value = _resolve_enrollment_policy(POLICY_AUTHENTICATOR_TYPES, user)
        if not value:
            return []

        if isinstance(value, set):
            raw = list(value)
        else:
            raw = [v.strip().lower() for v in str(value).split() if v.strip()]

        return [t for t in raw if t in VALID_AUTHENTICATOR_TYPES]

    def _handle_registration_phase1(self, params, user=None):
        """
        Generate WebAuthn registration challenge using Fido2Server.

        :return: dict with 'registerrequest' containing the
                 PublicKeyCredentialCreationOptions
        """
        # Build user entity - user and realm are required for FIDO2 enrollment
        if not user or not user.login or not user.realm:
            msg = "User information is required for FIDO2 token enrollment"
            raise ParameterError(msg)

        if not (rp_info := self._get_rp_id_and_name_from_policies(user=user)):
            g.audit["info"] = (
                f"`{POLICY_RP_ID}=` policy missing for realm `{user.realm}`"
            )
            msg = _(
                "To enroll FIDO2 tokens in realm `{0}`, a `{1}=` policy must be defined"
            )
            raise TokenAdminError(msg.format(user.realm, POLICY_RP_ID), id=1901)
        rp_id, rp_name = rp_info["rp_id"], rp_info["rp_name"]

        # log.info(f"_handle_registration_phase1: {rp_id=} {rp_name=}")
        self.addToTokenInfo(TOKEN_INFO_RP_ID, rp_id)
        self.addToTokenInfo(TOKEN_INFO_RP_NAME, rp_name)

        # Determine attestation and user verification preferences from policies
        attestation_preference = self._get_attestation_preference(user=user)
        uv_requirement = self._get_user_verification_requirement(user=user)
        rk_requirement = self._get_resident_key_requirement(user=user)

        # Save attestation conveyance for phase 2 validation
        self.addToTokenInfo(
            TOKEN_INFO_ATTESTATION_CONVEYANCE, attestation_preference.value
        )

        # Determine preferred authenticator types from policy
        authenticator_types = self._get_authenticator_types(user=user)
        authenticator_type_options = compute_authenticator_types_options(
            authenticator_types
        )

        # Include realm in name for clarity in passkey managers (Chrome, etc.)
        # WebAuthn user.name and user.displayName default to the linotp username.
        # These values can be overridden when a tokenlabel policy is applied.
        label = get_tokenlabel(
            self.getSerial(),
            user=user.login,
            realm=user.realm,
            description=self.getDescription(),
        )
        user_name = label
        user_display_name = user_name
        user_id = user_name.encode("utf-8")

        # Build user entity
        user_entity = PublicKeyCredentialUserEntity(
            id=user_id,
            name=user_name,
            display_name=user_display_name,
        )

        # Call Fido2Server.register_begin() to generate challenge and options
        options, state = self._get_fido2_server(
            attestation=attestation_preference,
        ).register_begin(
            user=user_entity,
            user_verification=uv_requirement,
            resident_key_requirement=rk_requirement,
            authenticator_attachment=authenticator_type_options.get(
                "authenticator_attachment", None
            ),
        )

        # Build response dict and inject WebAuthn L3 hints if configured
        register_request = dict(options.public_key)
        if "hints" in authenticator_type_options:
            register_request["hints"] = authenticator_type_options["hints"]

        # Serialize state for phase 2 (contains challenge + user_verification preference)
        state_json = self._serialize_state(state)
        self.addToTokenInfo(TOKEN_INFO_REGISTRATION_CHALLENGE, state_json)

        log.info("FIDO2 registration phase 1 initiated for token %s", self.getSerial())

        return {"registerrequest": register_request}

    def _handle_registration_phase2(self, params, user=None):
        """
        Verify WebAuthn attestation response and store the credential.

        Uses Fido2Server.register_complete() to verify the attestation.
        Expects 'otpkey' as a dict with the attestation response.
        If the value is a string instead it is assumed to be JSON and decoded.

        :return: dict with registration result details
        """
        attestation_response = params.get("otpkey")
        if attestation_response is None:
            msg = "No otpkey set (expected FIDO2 attestation response)"
            raise ParameterError(msg)
        if isinstance(attestation_response, str):
            try:
                attestation_response = json.loads(attestation_response)
            except Exception as ex:
                msg = f"Attestation response is invalid JSON ({ex})"
                raise ParameterError(msg) from ex

        # Retrieve registration state from phase 1
        state_json = self.getFromTokenInfo(TOKEN_INFO_REGISTRATION_CHALLENGE, None)
        if not state_json:
            msg = "No registration state found in token info."
            raise ParameterError(msg)

        state = self._deserialize_state(state_json)

        # Verify attestation using Fido2Server
        # Response is expected in nested format from client:
        # {id, rawId, type, response: {clientDataJSON, attestationObject}}
        try:
            auth_data = self._get_fido2_server().register_complete(
                state, attestation_response
            )
        except ValueError as exx:
            msg = f"FIDO2 registration verification failed: {exx}"
            raise ParameterError(msg) from exx

        # Extract credential data
        if auth_data.credential_data is None:
            msg = "No credential data in attestation response"
            raise ParameterError(msg)

        credential_data = auth_data.credential_data
        credential_id = credential_data.credential_id
        public_key = credential_data.public_key
        public_key_cbor = cbor_encode(public_key)

        # ----------------------------------------------------------
        # Extract attestation details for extended properties
        # ----------------------------------------------------------
        # We need to re-parse the attestation object to get format and certificate
        attestation_object_raw = websafe_decode(
            attestation_response["response"]["attestationObject"]
        )
        attestation_object = AttestationObject(attestation_object_raw)

        # AAGUID — unique identifier for the authenticator model
        aaguid_str = str(credential_data.aaguid)

        # Attestation format ("packed", "none", "tpm", "apple", etc.)
        attestation_fmt = attestation_object.fmt

        # Public key algorithm (COSE ID: -7=ES256, -257=RS256, -8=EdDSA)
        pub_key_alg = public_key.ALGORITHM

        # Authenticator data flags
        flags_byte = int(auth_data.flags)
        backup_eligible = auth_data.is_backup_eligible()
        backed_up = auth_data.is_backed_up()
        user_verified = auth_data.is_user_verified()

        # Attestation certificate (if provided in attestation statement)
        attestation_cert_b64 = None
        att_stmt = attestation_object.att_stmt
        if att_stmt and "x5c" in att_stmt:
            x5c = att_stmt["x5c"]
            if x5c and len(x5c) > 0:
                # Store the leaf certificate as base64-encoded DER
                attestation_cert_b64 = base64.b64encode(bytes(x5c[0])).decode("ascii")

        # Registration timestamp
        registered_at = datetime.now(UTC).isoformat()

        # Store the credential using dataclass (with extended fields)
        cred = Fido2Credential(
            credential_id=websafe_encode(credential_id),
            public_key=websafe_encode(public_key_cbor),
            sign_count=auth_data.counter,
            rp_id=self.getFromTokenInfo(TOKEN_INFO_RP_ID),
            aaguid=aaguid_str,
            attestation_format=attestation_fmt,
            public_key_algorithm=pub_key_alg,
            auth_data_flags=flags_byte,
            backup_eligible=backup_eligible,
            backed_up=backed_up,
            user_verified_at_reg=user_verified,
            attestation_cert_b64=attestation_cert_b64,
            registered_at=registered_at,
        )

        self.addToTokenInfo(TOKEN_INFO_CREDENTIAL, cred.to_json())
        self.addToTokenInfo(TOKEN_INFO_PHASE, TokenPhase.AUTHENTICATION)
        self.addToTokenInfo(TOKEN_INFO_COUNTER, str(auth_data.counter))

        # Remove the registration state
        self.removeFromTokenInfo(TOKEN_INFO_REGISTRATION_CHALLENGE)

        # Activate the token
        self.token.LinOtpIsactive = True

        log.info(
            "FIDO2 registration completed for token %s "
            "(credential_id=%s, aaguid=%s, fmt=%s, alg=%s, "
            "BE=%s, BS=%s, UV=%s)",
            self.getSerial(),
            websafe_encode(credential_id),
            aaguid_str,
            attestation_fmt,
            pub_key_alg,
            backup_eligible,
            backed_up,
            user_verified,
        )

        return {}

    def get_enrollment_status(self):
        """
        return the enrollemnt status
        """
        current_phase = self.getFromTokenInfo(TOKEN_INFO_PHASE)

        if current_phase == TokenPhase.AUTHENTICATION:
            return {"status": "completed"}
        return {"status": "unpaired"}

    # ---------------------------------------------------------------------- --
    # Authentication (Assertion) - Challenge/Response
    # ---------------------------------------------------------------------- --

    def splitPinPass(self, passw: str):
        """
        Split pin and otp from the password.

        For FIDO2, the OTP part is a JSON string.
        We look for the start of JSON data since the pin might contain `{`.

        :param passw: the input string (pin + otp)
        :return: tuple of (pin, otpval)
        """
        remaining = passw
        pin = ""

        while remaining:
            # Partition on first '{'
            part_pin, sep, part_otp = remaining.partition("{")

            if not sep:
                # No '{' found - entire remaining string is PIN
                pin += remaining
                return pin, ""

            pin += part_pin
            potential_json = sep + part_otp

            # Try to parse as JSON
            try:
                json.loads(potential_json)
                # Valid JSON found!
                return pin, potential_json
            except (json.JSONDecodeError, ValueError):
                # Not valid JSON yet, continue searching
                # Move past this '{' and keep looking
                pin += sep
                remaining = part_otp

        # Exhausted all '{' characters - no valid JSON found
        return passw, ""

    def is_challenge_request(self, passw, user, options=None):
        """
        Check if the request triggers a FIDO2 challenge.

        A FIDO2 challenge is triggered when the user provides a correct PIN.

        :param passw: password, which should be the PIN
        :param user: the user from the authentication request
        :param options: additional request parameters
        :return: True if this is a challenge request
        """
        return check_pin(self, passw, user=user, options=options)

    def createChallenge(self, transactionid, options=None):
        """
        Create a FIDO2 authentication challenge using Fido2Server.

        Generates a ``PublicKeyCredentialRequestOptions`` object that the
        client uses to invoke ``navigator.credentials.get()``.

        :param transactionid: the transaction ID for this challenge
        :param options: request options
        :return: tuple of (success, message, data, attributes)
        """
        cred = self._get_stored_credential()

        # Build allowCredentials list from the stored credential
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=websafe_decode(cred.credential_id),
            )
        ]

        # Determine user verification requirement from policy
        # Build a User object from the token's owner info for policy lookup
        username = self.getUsername()
        realms = self.getRealms()
        token_user = (
            User(login=username, realm=realms[0]) if username and realms else None
        )
        uv_requirement = self._get_user_verification_requirement(user=token_user)

        # Call Fido2Server.authenticate_begin() to generate challenge and options
        options_obj, state = self._get_fido2_server().authenticate_begin(
            credentials=allow_credentials,
            user_verification=uv_requirement,
        )

        # Serialize state for later verification (contains challenge + user_verification)
        state_json = self._serialize_state(state)

        # Build challenge data with serialized state
        sign_request = dict(options_obj.public_key)
        challenge_data = {
            "challenge": state_json,  # Contains state for authentication_complete
            "signrequest": sign_request,
        }

        message = "FIDO2 authentication challenge"
        attributes = {"signrequest": sign_request}

        return (True, message, challenge_data, attributes)

    def is_challenge_response(self, passw, user, options=None, challenges=None):
        """
        Check if the request contains a FIDO2 assertion response.

        :param passw: the password/response
        :param user: the requesting user
        :param options: additional request parameters
        :param challenges: list of open challenges
        :return: True if this is a challenge response
        """
        if not challenges:
            return False

        # Check for transactionid/state in options (standard mechanism)
        return bool(options and ("state" in options or "transactionid" in options))

    def checkResponse4Challenge(self, user, passw, options=None, challenges=None):
        """
        Verify a FIDO2 assertion response against a pending challenge.

        :param user: the requesting user
        :param passw: the password (assertion response JSON)
        :param options: additional request parameters
        :param challenges: list of pending challenges
        :return: tuple of (otp_counter, matching_challenges)
        """
        if not challenges:
            return -1, []

        otp_counter = -1
        matching_challenges = []

        for challenge in challenges:
            # Get the saved challenge data
            saved_challenge_b64 = self._parse_challenge_data(challenge)
            if not saved_challenge_b64:
                log.debug(
                    "Could not find challenge data for challenge %s", challenge.transid
                )
                continue

            # Verify the assertion response
            _otp_counter = self._verify_assertion(passw, saved_challenge_b64)
            if _otp_counter >= 0:
                matching_challenges.append(challenge)
                otp_counter = _otp_counter

        return otp_counter, matching_challenges

    def _verify_assertion(self, passw, saved_challenge_state_json):
        """
        Verify a FIDO2 assertion response using Fido2Server.

        :param passw: the JSON assertion response string
        :param saved_challenge_state_json: the JSON-serialized state from Fido2Server
        :return: 0 on success, -1 on failure
        """
        # Deserialize state from challenge
        try:
            state = self._deserialize_state(saved_challenge_state_json)
        except ParameterError as exx:
            log.debug("Failed to parse challenge state: %r", exx)
            return -1

        # Parse assertion response
        try:
            resp_data = json.loads(passw)
        except (ValueError, TypeError) as exx:
            log.debug("Invalid JSON in FIDO2 assertion response: %r", exx)
            return -1

        # Reconstruct stored credential for verification
        try:
            attested_cred = self._reconstruct_attested_credential()
        except ParameterError as exx:
            log.warning("Failed to reconstruct credential: %r", exx)
            return -1

        # Verify assertion using Fido2Server
        # Response is expected in nested format from client:
        # {id, rawId, type, response: {clientDataJSON, authenticatorData, signature}}
        try:
            self._get_fido2_server().authenticate_complete(
                state, [attested_cred], resp_data
            )
        except ValueError as exx:
            log.warning(
                "FIDO2 assertion verification failed for token %s: %s",
                self.getSerial(),
                exx,
            )
            return -1

        # At this point, all cryptographic verification is complete (done by Fido2Server)
        # Now extract the counter from the response and verify counter/update state

        # Parse authenticator data to get counter and verify it
        try:
            authenticator_data_raw = websafe_decode(
                resp_data["response"]["authenticatorData"]
            )
            auth_data = AuthenticatorData(authenticator_data_raw)
        except (KeyError, ValueError) as exx:
            log.warning("Failed to parse authenticator data: %r", exx)
            return -1

        # Verify counter (protection against cloned authenticators)
        prev_counter = int(self.getFromTokenInfo(TOKEN_INFO_COUNTER, "0"))
        new_counter = auth_data.counter

        if new_counter != 0 and new_counter <= prev_counter:
            # counter of 0 means the authenticator doesn't support counters
            log.warning(
                "FIDO2 counter did not increase for token %s: "
                "prev=%d, new=%d (possible cloned authenticator!)",
                self.getSerial(),
                prev_counter,
                new_counter,
            )
            # Deactivate token on counter mismatch to prevent cloning attacks
            self.token.LinOtpIsactive = False
            return -1

        # Update the counter in token info
        self.addToTokenInfo(TOKEN_INFO_COUNTER, str(new_counter))

        # Retrieve and update credential data
        cred = self._get_stored_credential()

        # Update sign count in credential
        cred.sign_count = new_counter

        # Update backup state — BS flag can change between authentications
        # (e.g., credential synced after registration)
        cred.backed_up = auth_data.is_backed_up()
        user_verified = auth_data.is_user_verified()

        self.addToTokenInfo(TOKEN_INFO_CREDENTIAL, cred.to_json())

        # Track last authentication timestamp and user verification status
        now_iso = datetime.now(UTC).isoformat()
        self.addToTokenInfo(TOKEN_INFO_LAST_AUTH, now_iso)
        self.addToTokenInfo(TOKEN_INFO_LAST_AUTH_UV, str(user_verified))

        log.info(
            "FIDO2 authentication successful for token %s (counter=%d, UV=%s)",
            self.getSerial(),
            new_counter,
            user_verified,
        )
        return 0

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        Standard OTP check callback.

        For FIDO2, OTP checking is handled in checkResponse4Challenge.
        This method is provided for compatibility but delegates to the
        assertion verification.

        :param anOtpVal: the OTP value (FIDO2 assertion JSON)
        :param counter: start counter (unused)
        :param window: window (unused)
        :param options: additional options including the challenge data
        :return: 0 on success, -1 on failure
        """
        if not options:
            return -1

        challenges = options.get("challenges", [])
        transactionid = options.get("transactionid")

        if not challenges or not transactionid:
            return -1

        # Find the matching challenge
        for challenge in challenges:
            if challenge.transid == transactionid:
                saved_challenge_b64 = self._parse_challenge_data(challenge)
                if saved_challenge_b64:
                    return self._verify_assertion(anOtpVal, saved_challenge_b64)

        return -1
