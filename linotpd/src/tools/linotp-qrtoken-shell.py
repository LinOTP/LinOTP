#!/usr/bin/python2 -i

import sys
import requests
import base64

if not sys.flags.interactive:
    print("qrtoken shell must be run in interactive mode (python -i)")
    sys.exit(1)

print(' _____     _____            _____ _       _ _  \n'
      ' |     |___|_   _|___ ___   |   __| |_ ___| | |\n'
      ' |  |  |  _| | | | .\'|   |  |__   |   | -_| | |\n'
      ' |__  _|_|   |_| |__,|_|_|  |_____|_|_|___|_|_|\n'
      '    |__| \n')

print("Welcome to the qrtoken shell.")

# ------------------------------------------------------------------------------

secret_key_file = raw_input('Please enter the location of your '
                            'secret key file:')

# ------------------------------------------------------------------------------

with open(secret_key_file) as f:

    content = f.read()

    if not content.startswith('qrtokensk:'):
        print('Curve 25519 / QR secret key has an invalid '
              'format. Must begin with \'qrtokensk:\'')
        sys.exit(1)

    b64_encoded_secret_key = content[len('qrtokensk:'):]
    secret_key = base64.b64decode(b64_encoded_secret_key)

    if len(secret_key) != 32:
        print('Curve 25519 / QR secret key has an invalid '
              'format. Key must be 32 bytes long')
        sys.exit(1)

# ------------------------------------------------------------------------------

public_key_file = raw_input('Please enter the location of your '
                            'public key file:')

with open(public_key_file) as f:

    content = f.read()

    if not content.startswith('qrtokenpk:'):
        print('Curve 25519 / QR public key has an invalid '
              'format. Must begin with \'qrtokenpk:\'')
        sys.exit(1)

    b64_encoded_public_key = content[len('qrtokenpk:'):]
    public_key = base64.b64decode(b64_encoded_public_key)

    if len(public_key) != 32:
        print('Curve 25519 / QR public key has an invalid '
              'format. Key must be 32 bytes long')
        sys.exit(1)

# ------------------------------------------------------------------------------

SESSION = raw_input('Please enter the session string')

if not SESSION:
    try:
        response = requests.get('http://localhost:5001/admin/getsession')
        SESSION = response.cookies['admin_session']
    except:
        print 'linotp server must be running on localhost:5001'

cookies = {'admin_session': SESSION}

# ------------------------------------------------------------------------------


def commands():

    print('* parse_pairing_url("lseqr://pair/...")\t\t\tShows the data of '
          'the supplied pairing url\n'
          '* send_pairing_response("lseqr://pair/...")\t\tSends a pairing '
          'response based on the supplied url to admin/init\n'
          '* parse_challenge_url("lseqr://chal/...")\t\tShows the data of '
          'the supplied challenge url\n'
          '* send_challenge_response("lseqr://chal/...")\t\tSends a challenge '
          'response based on the supplied url to validate/check_t')

# ------------------------------------------------------------------------------

from collections import defaultdict
import struct

token_db = defaultdict(dict)

TYPE_QRTOKEN        = 2
QRTOKEN_VERSION     = 0
RESPONSE_VERSION  = 0

FLAG_PAIR_SERIAL  = 1 << 0
FLAG_PAIR_CBURL   = 1 << 1
FLAG_PAIR_CBSMS   = 1 << 2
FLAG_PAIR_DIGITS  = 1 << 3
FLAG_PAIR_HMAC    = 1 << 4

QRTOKEN_CT_FREE     = 0
QRTOKEN_CT_PAIR     = 1
QRTOKEN_CT_AUTH     = 2

FLAG_QR_COMP      = 1
FLAG_QR_HAVE_URL  = 2
FLAG_QR_HAVE_SMS  = 4
FLAG_QR_SRVSIG    = 8

# ------------------------------------------------------------------------------

import os
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Cipher import AES

#-------------------------------------------------------------------------------

def encode_base64_urlsafe(data):
    """ encodes a string with urlsafe base64 and removes its padding """
    return base64.urlsafe_b64encode(data).decode('utf8').rstrip('=')

def decode_base64_urlsafe(data):
    """ decodes a string encoded with :func encode_base64_urlsafe """
    return base64.urlsafe_b64decode(data.encode() + (-len(data) % 4)*b'=')

# ------------------------------------------------------------------------------

def parse_pairing_url(pairing_url):

    """
    parses the pairing url and saves the extracted data in
    the fake token database

    :param pairing_url: the pairing url received from the server
    :returns: user_token_id of newly created token
    """

    # extract metadata and the public key

    data_encoded = pairing_url[len('lseqr://pair/'):]
    data = decode_base64_urlsafe(data_encoded)
    version, token_type, flags = struct.unpack('<bbI', data[0:6])
    server_public_key = data[6:6+32]

    # validate protocol versions and type id

    if not token_type == TYPE_QRTOKEN:
        raise Exception("wrong token type in url")

    if not version == RESPONSE_VERSION:
        raise Exception('wrong pairing version')

    # --------------------------------------------------------------------------

    # extract custom data that may or may not be present
    # (depending on flags)

    custom_data = data[6+32:]

    token_serial = None
    if flags & FLAG_PAIR_SERIAL:
        token_serial, __, custom_data = custom_data.partition(b'\x00')

    callback_url = None
    if flags & FLAG_PAIR_CBURL:
        callback_url, __, custom_data = custom_data.partition(b'\x00')
    else:
        raise NotImplementedError('SMS is not implemented. Callback URL'
                                  'is mandatory.')

    callback_sms = None
    if flags & FLAG_PAIR_CBSMS:
        callback_sms, __, custom_data = custom_data.partition(b'\x00')

    # ----------------------------------------------------------------------

    # save token data for later use

    user_token_id = len(token_db)
    token_db[user_token_id] = {'serial': token_serial,
                               'server_public_key': server_public_key,
                               'callback_url': callback_url,
                               'callback_sms': callback_sms}

    # ----------------------------------------------------------------------

    print('Data in URL:')

    for key, value in token_db[user_token_id].items():
        if key == 'server_public_key':
            value = value.encode('hex')
        print('%s\n    %s\n' % (key, value))

    return user_token_id

# ------------------------------------------------------------------------------

def send_pairing_response(pairing_url):

    user_token_id = parse_pairing_url(pairing_url)
    serial = token_db[user_token_id]['serial']

    # ----------------------------------------------------------------------

    server_public_key = token_db[user_token_id]['server_public_key']

    pairing_response = b''
    pairing_response += struct.pack('<bbI', RESPONSE_VERSION,
                                    TYPE_QRTOKEN, user_token_id)

    pairing_response += public_key

    pairing_response += serial.encode('utf8') + b'\x00\x00'

    # ----------------------------------------------------------------------

    # create public diffie hellman component
    # (used to decrypt and verify the reponse)

    r = os.urandom(32)
    R = calc_dh_base(r)

    # ----------------------------------------------------------------------

    # derive encryption key and nonce

    ss = calc_dh(r, server_public_key)
    U = SHA256.new(ss).digest()
    encryption_key = U[0:16]
    nonce = U[16:32]

    # ----------------------------------------------------------------------

    # encrypt in EAX mode

    cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

    pairing_response = encode_base64_urlsafe(R + ciphertext + tag)


    params = {'session': SESSION, 'pairing_response': pairing_response,
              'type': 'qr' }

    r = requests.request('get', 'http://localhost:5001/admin/init',
                         params=params, cookies=cookies)

    print(r.status_code)
    print('----------------------------------')
    print(r.content)

# ------------------------------------------------------------------------------

def u64_to_transaction_id(u64_int):
    # HACK! counterpart to transaction_id_to_u64 in
    # lib.tokens.qrtokenclass
    rest = u64_int % 100
    if rest == 0:
        return str(u64_int / 100)
    else:
        before = u64_int // 100
        return '%s.%s' % (str(before), str(rest))

# ------------------------------------------------------------------------------

def parse_challenge_url(challenge_url):

    """ Parses a challenge url and prints its data """

    challenge_data_encoded = challenge_url[len('lseqr://chal/'):]
    challenge_data = decode_base64_urlsafe(challenge_data_encoded)

    # ----------------------------------------------------------------------

    # parse and verify header information in the
    # encrypted challenge data

    header = challenge_data[0:5]
    version, user_token_id = struct.unpack('<bI', header)
    if not version == QRTOKEN_VERSION:
        raise Exception('wrong qrtoken version')


    # ----------------------------------------------------------------------

    # get token from client token database

    token = token_db[user_token_id]

    # ----------------------------------------------------------------------

    # prepare decryption by seperating R from
    # ciphertext and tag

    R = challenge_data[5:5+32]
    ciphertext = challenge_data[5+32:-16]
    tag = challenge_data[-16:]

    # ----------------------------------------------------------------------

    # key derivation

    ss = calc_dh(secret_key, R)
    U1 = SHA256.new(ss).digest()
    U2 = SHA256.new(U1).digest()

    skA = U1[0:16]
    skB = U2[0:16]
    nonce = U2[16:32]

    # ----------------------------------------------------------------------

    # decrypt and verify challenge

    cipher = AES.new(skA, AES.MODE_EAX, nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # ----------------------------------------------------------------------

    # parse/check plaintext header

    pt_header = plaintext[0:10]
    content_type, flags, transaction_id = struct.unpack('<bbQ', pt_header)
    transaction_id = u64_to_transaction_id(transaction_id)

    # make sure a flag for the server signature is
    # present, if the content type is 'pairing'

    if content_type == QRTOKEN_CT_PAIR and not flags & FLAG_QR_SRVSIG:
        raise Exception('Ill formatted callenge url')

    # ----------------------------------------------------------------------

    # retrieve plaintext data depending on flags

    if flags & FLAG_QR_SRVSIG:

        # plaintext has a server signature as a header
        # extract it and check if it is correct

        server_signature = plaintext[10:10+32]
        data = plaintext[10+32:]

        # calculate secret

        server_public_key = token['server_public_key']
        secret = calc_dh(secret_key, server_public_key)

        # check hmac

        message = nonce + pt_header + data
        signed = HMAC.new(secret, msg=message, digestmod=SHA256).digest()

        if not server_signature == signed:
            raise Exception('HMAC signature check failed')

    else:

        # no server signature found - just remove
        # the plaintext header

        data = plaintext[10:]

        # we have to define an empty server signature in
        # here because we need it later to create the
        # client signature

        server_signature = b''

    # ----------------------------------------------------------------------

    # extract message and (optional) callback
    # parameters from data

    message, _, suffix = data.partition(b'\x00')

    callback_url = token['callback_url']
    if flags & FLAG_QR_HAVE_URL:
        callback_url, _, suffix = suffix.partition(b'\x00')

    callback_sms = token['callback_sms']
    if flags & FLAG_QR_HAVE_SMS:
        callback_sms, _, suffix = suffix.partition(b'\x00')

    # ----------------------------------------------------------------------

    # prepare the parsed challenge data

    challenge = {}
    challenge['message'] = message
    challenge['content_type'] = content_type
    challenge['callback_url'] = callback_url
    challenge['callback_sms'] = callback_sms
    challenge['transaction_id'] = transaction_id
    challenge['user_token_id'] = user_token_id

    # calculate signature and tan

    message = nonce + pt_header + data
    sig_hmac = HMAC.new(skB, message, digestmod=SHA256)
    sig = sig_hmac.digest()

    encoded_sig = encode_base64_urlsafe(sig)

    print('Data in URL:')

    for key, value in challenge.items():
        print('%s\n    %s\n' % (key, value))

    return challenge, encoded_sig

# ------------------------------------------------------------------------------

def send_challenge_response(challenge_url):

    challenge, sig = parse_challenge_url(challenge_url)

    print('Sending signature %s to server' % sig)

    params = { 'transactionid': challenge['transaction_id'],
               'pass': sig }

    r = requests.request('get', 'http://localhost:5001/validate/check_t',
                         params=params, cookies=cookies)

    print(r.status_code)
    print('----------------------------------')
    print(r.content)




print 'Thanks! Type commands() for a list of commands'
