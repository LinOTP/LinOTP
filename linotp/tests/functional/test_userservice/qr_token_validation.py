import json
import os
import struct

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base

from linotp.lib.crypto.utils import (
    decode_base64_urlsafe,
    dsa_to_dh_public,
    encode_base64_urlsafe,
    extract_tan,
)

FLAG_PAIR_PK = 1 << 0
FLAG_PAIR_SERIAL = 1 << 1
FLAG_PAIR_CBURL = 1 << 2
FLAG_PAIR_CBSMS = 1 << 3
FLAG_PAIR_DIGITS = 1 << 4
FLAG_PAIR_HMAC = 1 << 5

TYPE_QRTOKEN = 2
QRTOKEN_VERSION = 1
PAIR_RESPONSE_VERSION = 1
PAIRING_URL_VERSION = 2

QRTOKEN_CT_FREE = 0
QRTOKEN_CT_PAIR = 1
QRTOKEN_CT_AUTH = 2

FLAG_QR_COMP = 1
FLAG_QR_HAVE_URL = 2
FLAG_QR_HAVE_SMS = 4
FLAG_QR_SRVSIG = 8


class QR_Token_Validation:
    uri = "lseqr"
    tan_length = 8

    @staticmethod
    def u64_to_transaction_id(u64_int):
        # HACK! counterpart to transaction_id_to_u64 in
        # tokens.qrtokenclass

        rest = u64_int % 100
        before = u64_int // 100

        if rest == 0:
            return str(before)
        else:
            return "%d.%02d" % (before, rest)

    @staticmethod
    def create_keys():
        secret_key = os.urandom(32)
        public_key = calc_dh_base(secret_key)
        return secret_key, public_key

    @staticmethod
    def create_user_token_by_pairing_url(pairing_url, pin="1234"):
        """
        parses the pairing url and saves the extracted data in
        the fake token database of this test class.

        :param pairing_url: the pairing url received from the server
        :returns: dict with all information
                return {
                    'serial': token_serial.decode(),
                    'server_public_key': server_public_key,
                    'partition': partition,
                    'callback_url': callback_url.decode(),
                    'callback_sms': callback_sms.decode(),
                    'pin': pin}
        """

        # extract metadata and the public key

        data_encoded = pairing_url[len(QR_Token_Validation.uri + "://pair/") :]
        data = decode_base64_urlsafe(data_encoded)
        version, token_type, flags = struct.unpack("<bbI", data[0:6])
        partition = struct.unpack("<I", data[6:10])[0]

        server_public_key_dsa = data[10 : 10 + 32]
        server_public_key = dsa_to_dh_public(server_public_key_dsa)

        # validate protocol versions and type id

        assert token_type == TYPE_QRTOKEN
        assert version == PAIRING_URL_VERSION

        # ------------------------------------------------------------------- --

        # extract custom data that may or may not be present
        # (depending on flags)

        custom_data = data[10 + 32 :]

        token_serial = None
        if flags & FLAG_PAIR_SERIAL:
            token_serial, __, custom_data = custom_data.partition(b"\x00")

        callback_url = None
        if flags & FLAG_PAIR_CBURL:
            callback_url, __, custom_data = custom_data.partition(b"\x00")
        else:
            raise NotImplementedError(
                "SMS is not implemented. Callback URLis mandatory."
            )

        callback_sms = None
        if flags & FLAG_PAIR_CBSMS:
            callback_sms, __, custom_data = custom_data.partition(b"\x00")

        # ------------------------------------------------------------------- --

        # save token data for later use

        ret = {
            "serial": token_serial.decode(),
            "server_public_key": server_public_key,
            "partition": partition,
            "pin": pin,
        }

        if callback_sms:
            ret["callback_sms"] = callback_sms.decode()

        if callback_url:
            ret["callback_url"] = callback_url.decode()

        return ret

    @staticmethod
    def claculate_challenge_response(challenge_url, token_info, secret_key):
        return QR_Token_Validation.decrypt_and_verify_challenge(
            challenge_url, token_info, secret_key
        )

    @staticmethod
    def decrypt_and_verify_challenge(challenge_url, token_info, secret_key):
        """
        Decrypts the data packed in the challenge url, verifies
        its content, returns the parsed data as a dictionary,
        calculates and returns the signature and TAN.

        The calling method must then send the signature/TAN
        back to the server. (The reason for this control flow
        is that the challenge data must be checked in different
        scenarios, e.g. when we have a pairing the data must be
        checked by the method that simulates the pairing)

        :param challenge_url: the challenge url as sent by the server

        :returns: (challenge, signature, tan)

            challenge has the keys

                * message - the signed message sent from the server
                * content_type - one of the three values QRTOKEN_CT_PAIR,
                    QRTOKEN_CT_FREE or QRTOKEN_CT_AUTH
                    (all defined in this module
                * callback_url (optional) - the url to which the challenge
                    response should be set
                * callback_sms (optional) - the sms number the challenge
                    can be sent to (typicall used as a fallback)
                * transaction_id - used to identify the challenge
                    on the server
                * user_token_id - used to identify the token in the
                    user database for which this challenge was created

            signature is the generated user signature used to
            respond to the challenge

            tan is the TAN-Number used as a substitute if the signature
            cant' be sent be the server (is generated from signature)
        """

        challenge_data_encoded = challenge_url[
            len(QR_Token_Validation.uri + "://chal/") :
        ]
        challenge_data = decode_base64_urlsafe(challenge_data_encoded)

        # ------------------------------------------------------------------- --

        # parse and verify header information in the
        # encrypted challenge data

        header = challenge_data[0:5]
        version, user_token_id = struct.unpack("<bI", header)
        assert version == QRTOKEN_VERSION

        # ------------------------------------------------------------------- --

        # get token from client token database

        # ------------------------------------------------------------------- --

        # prepare decryption by seperating R from
        # ciphertext and tag

        R = challenge_data[5 : 5 + 32]
        ciphertext = challenge_data[5 + 32 : -16]
        tag = challenge_data[-16:]

        # ------------------------------------------------------------------- --

        # key derivation

        ss = calc_dh(secret_key, R)
        U1 = SHA256.new(ss).digest()
        U2 = SHA256.new(U1).digest()

        skA = U1[0:16]
        skB = U2[0:16]
        nonce = U2[16:32]

        # ------------------------------------------------------------------- --

        # decrypt and verify challenge

        cipher = AES.new(skA, AES.MODE_EAX, nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # ------------------------------------------------------------------- --

        # parse/check plaintext header

        pt_header = plaintext[0:10]
        content_type, flags, transaction_id = struct.unpack("<bbQ", pt_header)
        transaction_id = QR_Token_Validation.u64_to_transaction_id(transaction_id)

        # make sure a flag for the server signature is
        # present, if the content type is 'pairing'

        if content_type == QRTOKEN_CT_PAIR:
            assert flags & FLAG_QR_SRVSIG

        # ------------------------------------------------------------------- --

        # retrieve plaintext data depending on flags

        if flags & FLAG_QR_SRVSIG:
            # plaintext has a server signature as a header
            # extract it and check if it is correct

            server_signature = plaintext[10 : 10 + 32]
            data = plaintext[10 + 32 :]

            # calculate secret

            server_public_key = token_info["server_public_key"]
            secret = calc_dh(secret_key, server_public_key)

            # check hmac

            message = nonce + pt_header + data
            signed = HMAC.new(secret, msg=message, digestmod=SHA256).digest()
            assert server_signature == signed

        else:
            # no server signature found - just remove
            # the plaintext header

            data = plaintext[10:]

            # we have to define an empty server signature in
            # here because we need it later to create the
            # client signature

            server_signature = b""

        # ------------------------------------------------------------------- --

        # extract message and (optional) callback
        # parameters from data

        message, _, suffix = data.partition(b"\x00")

        callback_url = token_info.get("callback_url")
        if flags & FLAG_QR_HAVE_URL:
            callback_url, _, suffix = suffix.partition(b"\x00")

        callback_sms = token_info.get("callback_sms")
        if flags & FLAG_QR_HAVE_SMS:
            callback_sms, _, suffix = suffix.partition(b"\x00")

        # ------------------------------------------------------------------- --

        # prepare the parsed challenge data

        challenge = {}
        challenge["message"] = message.decode("utf-8")
        challenge["content_type"] = content_type
        challenge["transaction_id"] = transaction_id
        challenge["user_token_id"] = user_token_id

        if callback_url:
            challenge["callback_url"] = callback_url.decode("utf-8")
        if callback_sms:
            challenge["callback_sms"] = callback_sms.decode("utf-8")

        # calculate signature and tan

        message_bin = nonce + pt_header + server_signature + data
        sig_hmac = HMAC.new(skB, message_bin, digestmod=SHA256)
        sig = sig_hmac.digest()

        tan = extract_tan(sig, QR_Token_Validation.tan_length)
        encoded_sig = encode_base64_urlsafe(sig)

        return challenge, encoded_sig, tan

    @staticmethod
    def get_pairing_url_from_response(response):
        """
        response should contain pairing url, check if it was
        sent and validate
        """

        response_dict = json.loads(response.body)
        assert "pairing_url" in response_dict.get("detail", {})

        pairing_url = response_dict.get("detail", {}).get("pairing_url")
        assert pairing_url is not None
        assert pairing_url.startswith(QR_Token_Validation.uri + "://pair/")

        return pairing_url

    @staticmethod
    def create_pairing_response(public_key, token_info, token_id=1):
        """
        Creates a base64-encoded pairing response that identifies
        the token by its serial

        :param user_token_id: the token id (primary key for the user token db)
        :returns base64 encoded pairing response
        """

        token_serial = token_info["serial"]
        server_public_key = token_info["server_public_key"]
        partition = token_info["partition"]

        header = struct.pack("<bI", PAIR_RESPONSE_VERSION, partition)

        pairing_response = b""
        pairing_response += struct.pack("<bI", TYPE_QRTOKEN, token_id)

        pairing_response += public_key

        pairing_response += token_serial.encode("utf8") + b"\x00\x00"

        # ------------------------------------------------------------------- --

        # create public diffie hellman component
        # (used to decrypt and verify the reponse)

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        ss = calc_dh(r, server_public_key)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------- --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        return encode_base64_urlsafe(header + R + ciphertext + tag)
