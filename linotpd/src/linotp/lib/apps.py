# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

This file contains utilities to generates the URL for smartphone apps like
                google authenticator
                oath token

"""

import binascii
import base64


import urllib

import logging
log = logging.getLogger(__name__)

from linotp.lib.policy import get_tokenlabel
from urllib import quote

#######################################
def create_google_authenticator(param):
    '''
    create url for google authenticator

    :param param: request dictionary
    :return: string with google url
    '''

    serial = param.get("serial", None)

    digits = param.get("otplen", None)

    otpkey = param.get("otpkey", None)
    if len(otpkey) == 0:
        raise Exception('Failed to create token url due to missing seed!')
    key = base64.b32encode(binascii.unhexlify(otpkey))
    key = key.strip("=")

    algo = param.get("hashlib", "sha1") or "sha1"
    algo = algo.upper()
    if algo not in['SHA1', 'SHA256', 'SHA512' , 'MD5']:
        algo = 'SHA1'

    typ = param.get("type", 'hotp')
    if typ.lower() == 'hmac':
        typ = 'hotp'
    if not typ.lower() in ['totp', 'hotp']:
        raise Exception('not supported otpauth token type: %r' % typ)

    url_param = {}
    url_param['secret'] = key
    if digits != '6':
        url_param['digits'] = digits
    url_param['counter'] = 0
    if algo != 'SHA1':
        url_param['algorithm'] = algo

    if 'timeStep' in param:
        url_param['period'] = param.get('timeStep')


    ga = "otpauth://%s/%s" % (typ, serial)
    qg_param = urllib.urlencode(url_param)

    base_len = len(ga) + len(qg_param)
    max_len = 400
    allowed_label_len = max_len - base_len
    log.debug("[create_google_authenticator_url] we got %s characters"
              " left for the token label" % str(allowed_label_len))

    # show the user login in the token prefix
    if len(param.get('user.login', '')) > 0:
        label = get_tokenlabel(param.get('user.login', ''), param.get('user.realm', ''), serial)
        label = label[0:allowed_label_len]
    else:
        label = serial
        if len(param.get('description', '')) > 0:
            label = label + ':' + param.get('description')
        label = label[0:allowed_label_len]

    url_label = quote(label)
    ga = "otpauth://%s/%s" % (typ, url_label)
    ga = "%s?%s" % (ga, qg_param)

    log.debug("[_create_google_authenticator] google authenticator: %r" % ga[:20])
    return ga






def create_google_authenticator_url(user, realm, key, type="hmac", serial=""):
    '''
    This creates the google authenticator URL.
    This url may only be 119 characters long.
    Otherwise we qrcode.js can not create the qrcode.
    If the URL would be longer, we shorten the username

    We expect the key to be hexlified!
    '''
    # policy depends on some lib.util

    if "hmac" == type.lower():
        type = "hotp"

    label = ""

    key_bin = binascii.unhexlify(key)
    # also strip the padding =, as it will get problems with the google app.
    otpkey = base64.b32encode(key_bin).strip('=')

    # 'url' : "otpauth://hotp/%s?secret=%s&counter=0" % ( user@realm, otpkey )
    base_len = len("otpauth://%s/?secret=%s&counter=0" % (type, otpkey))
    max_len = 119
    allowed_label_len = max_len - base_len
    log.debug("[create_google_authenticator_url] we got %s characters left for the token label" % str(allowed_label_len))

    label = get_tokenlabel(user, realm, serial)
    label = label[0:allowed_label_len]

    url_label = quote(label)

    return "otpauth://%s/%s?secret=%s&counter=0" % (type, url_label, otpkey)

def create_oathtoken_url(user, realm, otpkey, type="hmac", serial=""):
    # 'url' : 'oathtoken:///addToken?name='+serial +
    #                '&key='+otpkey+
    #                '&timeBased=false&counter=0&numDigites=6&lockdown=true',

    timebased = ""
    if "totp" == type.lower():
        timebased = "&timeBased=true"

    label = get_tokenlabel(user, realm, serial)
    url_label = quote(label)

    url = "oathtoken:///addToken?name=%s&lockdown=true&key=%s%s" % (
                                                                  url_label,
                                                                  otpkey,
                                                                  timebased
                                                                  )
    return url

