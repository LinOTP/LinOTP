import struct
import os
import json

from typing import Dict, Tuple

from linotp.tests import CompatibleTestResponse

from linotp.lib.crypto.utils import dsa_to_dh_public
from linotp.lib.crypto.utils import dsa_to_dh_secret
from linotp.lib.crypto.utils import encode_base64_urlsafe
from linotp.lib.crypto.utils import decode_base64_urlsafe

from linotp.lib.util import int_from_bytes

from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from pysodium import crypto_sign_detached
from pysodium import crypto_sign_verify_detached
from pysodium import crypto_sign_keypair as gen_dsa_keypair

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

FLAG_PAIR_PK = 1 << 0
FLAG_PAIR_SERIAL = 1 << 1
FLAG_PAIR_CBURL = 1 << 2
FLAG_PAIR_CBSMS = 1 << 3
FLAG_PAIR_DIGITS = 1 << 4
FLAG_PAIR_HMAC = 1 << 5
PAIRING_URL_VERSION = 2
PAIR_RESPONSE_VERSION = 1

TYPE_PUSHTOKEN = 4
CHALLENGE_URL_VERSION = 2

CONTENT_TYPE_SIGNREQ = 0
CONTENT_TYPE_PAIRING = 1
CONTENT_TYPE_LOGIN = 2


class Push_Token_Validation:

    uri_schema = "lseqr"
    tan_length = 8

    @staticmethod
    def u64_to_transaction_id(u64_int: int) -> str:
        """Hack, convert the int transaction id into string representation

        which might contain subtransaction id identifier

        :param u64_int: int
        :return: string representaion of a tranasction id
        """

        rest = u64_int % 100
        before = u64_int // 100

        if rest == 0:
            return str(before)
        else:
            return "%d.%02d" % (before, rest)

    @staticmethod
    def create_keys() -> Tuple[bytes, bytes]:
        """Create a public private key pair."""
        return gen_dsa_keypair()

    @staticmethod
    def create_user_token_by_pairing_url(pairing_url: str, pin: str) -> Dict:
        """Parses the pairing url and return the extracted token data as dict.

        :param pairing_url: the pairing url received from the server
        :param pin: the pin of the token

        :returns: token info dict
        """

        # extract metadata and the public key

        data_encoded = pairing_url[
            len(Push_Token_Validation.uri_schema + "://pair/") :
        ]

        data = decode_base64_urlsafe(data_encoded)
        version, token_type, flags = struct.unpack("<bbI", data[0:6])
        partition = struct.unpack("<I", data[6:10])[0]

        server_public_key = data[10 : 10 + 32]

        # validate protocol versions and type id

        assert token_type == TYPE_PUSHTOKEN
        assert version == PAIRING_URL_VERSION

        # ------------------------------------------------------------------ --

        # extract custom data that may or may not be present
        # (depending on flags)

        custom_data = data[10 + 32 :]

        assert flags & FLAG_PAIR_SERIAL
        token_serial, __, custom_data = custom_data.partition(b"\x00")

        callback_url = None
        if flags & FLAG_PAIR_CBURL:
            callback_url, __, custom_data = custom_data.partition(b"\x00")
        else:
            raise NotImplementedError(
                "Callback URL is mandatory for PushToken"
            )

        # ------------------------------------------------------------------- --

        # save token data for later use

        token_info = {
            "serial": token_serial.decode(),
            "server_public_key": server_public_key,
            "partition": partition,
            "callback_url": callback_url.decode(),
            "token_id": 1,
            "pin": pin,
        }

        return token_info

    @staticmethod
    def decrypt_and_verify_challenge(
        challenge_url: str, token_info: Dict, secret_key: bytes, action: str
    ) -> Tuple[Dict, str]:
        """Decrypts the data packed in the challenge url, verifies the content.

        Returns the parsed data as a dictionary, calculates and returns the
        signature.

        The calling method must then send the signature
        back to the server. (The reason for this control flow
        is that the challenge data must be checked in different
        scenarios, e.g. when we have a pairing the data must be
        checked by the method that simulates the pairing)

        :param challenge_url: the challenge url as sent by the server
        :param action: a string identifier for the verification action
            (at the moment 'ACCEPT' or 'DENY')

        :returns: (challenge, signature)

            challenge has the keys

                * content_type - one of the three values CONTENT_TYPE_SIGNREQ,
                    CONTENT_TYPE_PAIRING or CONTENT_TYPE_LOGIN)
                    (all defined in this module)
                * transaction_id - used to identify the challenge
                    on the server
                * callback_url (optional) - the url to which the challenge
                    response should be set
                * user_token_id - used to identify the token in the
                    user database for which this challenge was created

            depending on the content type additional keys are present

                * for CONTENT_TYPE_PAIRING: serial
                * for CONTENT_TYPE_SIGNREQ: message
                * for CONTENT_TYPE_LOGIN: login, host

            signature is the generated user signature used to
            respond to the challenge
        """

        challenge_data_encoded = challenge_url[
            len(Push_Token_Validation.uri_schema + "://chal/") :
        ]
        challenge_data = decode_base64_urlsafe(challenge_data_encoded)

        # ------------------------------------------------------------------ --

        # parse and verify header information in the
        # encrypted challenge data

        header = challenge_data[0:5]
        version, user_token_id = struct.unpack("<bI", header)
        assert version == CHALLENGE_URL_VERSION

        # ------------------------------------------------------------------ --

        # get token from client token database

        server_public_key = token_info["server_public_key"]

        # ------------------------------------------------------------------ --

        # prepare decryption by seperating R from
        # ciphertext and server signature

        R = challenge_data[5 : 5 + 32]
        ciphertext = challenge_data[5 + 32 : -64]
        server_signature = challenge_data[-64:]

        # check signature

        data = challenge_data[0:-64]
        crypto_sign_verify_detached(server_signature, data, server_public_key)

        # ------------------------------------------------------------------ --

        # key derivation

        secret_key_dh = dsa_to_dh_secret(secret_key)
        ss = calc_dh(secret_key_dh, R)
        U = SHA256.new(ss).digest()

        sk = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------ --

        # decrypt and verify challenge

        nonce_as_int = int_from_bytes(nonce, byteorder="big")
        ctr = Counter.new(128, initial_value=nonce_as_int)
        cipher = AES.new(sk, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)

        # ------------------------------------------------------------------ --

        # parse/check plaintext header

        # 1 - for content type
        # 8 - for transaction id
        # 8 - for time stamp
        offset = 1 + 8 + 8

        pt_header = plaintext[0:offset]
        (content_type, transaction_id, _time_stamp) = struct.unpack(
            "<bQQ", pt_header
        )

        transaction_id = Push_Token_Validation.u64_to_transaction_id(
            transaction_id
        )

        # ------------------------------------------------------------------ --

        # prepare the parsed challenge data

        challenge = {}
        challenge["content_type"] = content_type

        # ------------------------------------------------------------------ --

        # retrieve plaintext data depending on content_type

        if content_type == CONTENT_TYPE_PAIRING:

            serial, callback_url, __ = plaintext[offset:].split(b"\x00")
            challenge["serial"] = serial.decode()

        elif content_type == CONTENT_TYPE_SIGNREQ:

            message, callback_url, __ = plaintext[offset:].split(b"\x00")
            challenge["message"] = message.decode()

        elif content_type == CONTENT_TYPE_LOGIN:

            login, host, callback_url, __ = plaintext[offset:].split(b"\x00")
            challenge["login"] = login.decode()
            challenge["host"] = host.decode()

        # ------------------------------------------------------------------ --

        # prepare the parsed challenge data

        challenge["callback_url"] = callback_url.decode()
        challenge["transaction_id"] = transaction_id
        challenge["user_token_id"] = user_token_id

        # calculate signature

        sig_base = (
            struct.pack("<b", CHALLENGE_URL_VERSION)
            + b"%s\0" % action.encode("utf-8")
            + server_signature
            + plaintext
        )

        sig = crypto_sign_detached(sig_base, secret_key)
        encoded_sig = encode_base64_urlsafe(sig)

        return challenge, encoded_sig

    @staticmethod
    def get_pairing_url_from_response(response: CompatibleTestResponse) -> str:
        """Extract the the pairing url from the response.

        response should contain pairing url, check if it was
        sent and validate
        """

        response_dict = response.json
        assert "pairing_url" in response_dict["detail"]

        pairing_url = response_dict["detail"]["pairing_url"]
        assert pairing_url is not None
        assert pairing_url.startswith(
            Push_Token_Validation.uri_schema + "://pair/"
        )

        return pairing_url

    @staticmethod
    def create_pairing_response(
        public_key: bytes,
        secret_key: bytes,
        token_info: Dict,
        gda: str = "DEADBEEF",
    ) -> str:
        """Creates a base64-encoded pairing response.

        :param public_key: the public key in bytes
        :param secret_key: the secret key in bytes
        :param token_info: the token_info dict
        :param user_token_id: the token id
        :param gda: the mobile device gda

        :returns base64 encoded pairing response
        """

        token_serial = token_info["serial"]
        token_id = token_info.get("token_id", 1)
        server_public_key = token_info["server_public_key"]
        partition = token_info["partition"]

        # ------------------------------------------------------------------ --

        # assemble header and plaintext

        header = struct.pack("<bI", PAIR_RESPONSE_VERSION, partition)

        pairing_response = b""
        pairing_response += struct.pack("<bI", TYPE_PUSHTOKEN, token_id)

        pairing_response += public_key

        pairing_response += token_serial.encode("utf8") + b"\x00\x00"
        pairing_response += gda.encode("utf-8") + b"\x00"

        signature = crypto_sign_detached(pairing_response, secret_key)
        pairing_response += signature

        # ------------------------------------------------------------------ --

        # create public diffie hellman component
        # (used to decrypt and verify the reponse)

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------ --

        # derive encryption key and nonce

        server_public_key_dh = dsa_to_dh_public(server_public_key)
        ss = calc_dh(r, server_public_key_dh)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------ --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        return encode_base64_urlsafe(header + R + ciphertext + tag)
