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

class NoOtpAuthTokenException(Exception):
    pass


def create_google_authenticator(param, user=None):
    '''
    create url for google authenticator

    :param param: request dictionary
    :return: string with google url
    '''

    typ = param.get("type", 'hotp')
    if typ.lower() == 'hmac':
        typ = 'hotp'

    if not typ.lower() in ['totp', 'hotp']:
        raise NoOtpAuthTokenException('not supported otpauth token type: %r'
                                      % typ)

    serial = param.get("serial", None)
    digits = param.get("otplen", '6')
    otpkey = param.get("otpkey", None)

    login = ''
    realm = ''

    if user:
        login = user.login or ''
        realm = user.realm or ''

    login = login or param.get('user.login', '')
    realm = realm or param.get('user.realm', '')

    url_param = {}

    if not otpkey:
        raise Exception('Failed to create token url due to missing seed!')
    key = base64.b32encode(binascii.unhexlify(otpkey))
    key = key.strip("=")

    algo = param.get("hashlib", "sha1") or "sha1"
    algo = algo.upper()
    if algo not in['SHA1', 'SHA256', 'SHA512', 'MD5']:
        algo = 'SHA1'

    if algo != 'SHA1':
        url_param['algorithm'] = algo

    url_param['secret'] = key

    # dont add default
    if digits != '6':
        url_param['digits'] = digits

    if typ not in ['totp']:
        url_param['counter'] = 0

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
    if len(login) > 0:
        label = get_tokenlabel(login, realm, serial)
        if len(param.get('description', '')) > 0 and '<d>' in label:
            label = label.replace('<d>', param.get('description'))

    else:
        label = serial or ''
        if len(param.get('description', '')) > 0:
            label = label + ':' + param.get('description')

    label = label[0:allowed_label_len]
    url_label = quote(label)

    ga = "otpauth://%s/%s?%s" % (typ, url_label, qg_param)
    log.debug("google authenticator: %r" % ga[:20])
    return ga


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

