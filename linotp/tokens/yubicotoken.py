# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
""" This file contains the Yubico token class"""

import binascii
import datetime
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from hashlib import sha1

import requests
from requests.exceptions import (
    ConnectionError,
    ConnectTimeout,
    ReadTimeout,
    Timeout,
    TooManyRedirects,
)

from linotp.lib.config import getFromConfig
from linotp.lib.error import ParameterError
from linotp.lib.resources import AllResourcesUnavailable, ResourceScheduler
from linotp.lib.type_utils import parse_timeout
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import TokenClass

YUBICO_LEN_ID = 12
YUBICO_LEN_OTP = 44

DEPRECATED_YUBICO_URL = "http://api.yubico.com/wsapi/2.0/verify"

FALLBACK_YUBICO_URL = ", ".join(
    [
        "https://api.yubico.com/wsapi/2.0/verify",
        "https://api2.yubico.com/wsapi/2.0/verify",
        "https://api3.yubico.com/wsapi/2.0/verify",
        "https://api4.yubico.com/wsapi/2.0/verify",
        "https://api5.yubico.com/wsapi/2.0/verify",
    ]
)

LINOTP_DOC_LINK = (
    "https://linotp.org/doc/latest/part-management/managingtokens/"
    "tokens-config.html?highlight=yubico#yubico-token-default-settings"
)

YUBICO_GETAPI_LINK = "https://upgrade.yubico.com/getapikey/"

APIKEY_UNCONFIGURED_ERROR = """
You need to provide an API key and ID for Yubico support.
Please register your own apiKey and apiId at the Yubico web site:"
  %s
Configure apiKey and apiId in the LinOTP token-config dialog.
Have a look at:
  %s"
""" % (
    YUBICO_GETAPI_LINK,
    LINOTP_DOC_LINK,
)


class YubicoApikeyException(Exception):
    pass


log = logging.getLogger(__name__)


@tokenclass_registry.class_entry("yubico")
@tokenclass_registry.class_entry("linotp.tokens.yubicotoken.YubicoTokenClass")
class YubicoTokenClass(TokenClass):
    """
    The Yubico Cloud token forwards an authentication request to the Yubico Cloud service.
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType("yubico")

        self.tokenid = ""

    @classmethod
    def getClassType(cls):
        return "yubico"

    @classmethod
    def getClassPrefix(cls):
        return "UBCM"

    @classmethod
    def getClassInfo(cls, key=None, ret="all"):
        """
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype: s.o.

        """

        res = {
            "type": "yubico",
            "title": "Yubico Token",
            "description": (
                "Yubico token to forward the authentication "
                "request to the Yubico Cloud authentication"
            ),
            "init": {
                "page": {
                    "html": "yubicotoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "yubicotoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "page": {
                    "html": "yubicotoken.mako",
                    "scope": "config",
                },
                "title": {
                    "html": "yubicotoken.mako",
                    "scope": "config.title",
                },
            },
            "selfservice": {
                "enroll": {
                    "page": {
                        "html": "yubicotoken.mako",
                        "scope": "selfservice.enroll",
                    },
                    "title": {
                        "html": "yubicotoken.mako",
                        "scope": "selfservice.title.enroll",
                    },
                },
            },
            "policy": {},
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res
        return ret

    def update(self, param):
        try:
            tokenid = param["yubico.tokenid"]
        except KeyError:
            raise ParameterError("Missing parameter: 'yubico.tokenid'")

        if len(tokenid) < YUBICO_LEN_ID:
            raise Exception(
                "The YubiKey token ID needs to be %i characters "
                "long!" % YUBICO_LEN_ID
            )

        if len(tokenid) > YUBICO_LEN_ID:
            tokenid = tokenid[:YUBICO_LEN_ID]

        self.tokenid = tokenid
        self.setOtpLen(44)

        TokenClass.update(self, param)

        self.addToTokenInfo("yubico.tokenid", self.tokenid)

        return

    def resync(self, otp1, otp2, options=None):
        """
        resync of yubico tokens - not supported!!
        """
        raise Exception("YUBICO token resync is not managed by LinOTP.")

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        Here we contact the Yubico Cloud server to validate the OtpVal.
        """

        pparams = {}

        yubico_url = getFromConfig("yubico.url", FALLBACK_YUBICO_URL)

        if yubico_url == DEPRECATED_YUBICO_URL:
            log.warning(
                "Usage of YUBICO_URL %r is deprecated!! ",
                DEPRECATED_YUBICO_URL,
            )

            # setups with old YUBICO URLS will be broken on yubico side
            # after 3th of February 2019
            third_feb_2019 = datetime.datetime(year=2019, month=2, day=3)

            if datetime.datetime.now() >= third_feb_2019:
                raise Exception(
                    "Usage of YUBICO_URL %r is deprecated!! "
                    % DEPRECATED_YUBICO_URL
                )

        apiId = getFromConfig("yubico.id")
        apiKey = getFromConfig("yubico.secret")

        if not apiKey or not apiId:
            log.error(APIKEY_UNCONFIGURED_ERROR)
            raise YubicoApikeyException(
                "Yubico apiKey or apiId not configured!"
            )

        tokenid = self.getFromTokenInfo("yubico.tokenid")
        if len(anOtpVal) < 12:
            log.warning("[checkOtp] The otpval is too short: %r", anOtpVal)
            return -1

        if anOtpVal[:12] != tokenid:
            log.warning(
                "[checkOtp] the tokenid in the OTP value does "
                "not match the assigned token!"
            )
            return -1

        timeout = getFromConfig("yubico.timeout")
        if timeout:
            pparams["timeout"] = parse_timeout(timeout)

        nonce = binascii.hexlify(os.urandom(20)).decode()

        p = urllib.parse.urlencode(
            {"nonce": nonce, "otp": anOtpVal, "id": apiId}
        )

        yubico_urls = [x.strip() for x in yubico_url.split(",")]

        res_scheduler = ResourceScheduler(tries=2, uri_list=yubico_urls)

        for uri in next(res_scheduler):
            try:
                URL = "%s?%s" % (uri, p)

                response = requests.get(URL, **pparams)

                if response.ok:
                    return self._check_yubico_response(
                        nonce, apiKey, response.content.decode()
                    )

                log.info("Failed to validate yubico request %r", response)

                return -1

            except (
                Timeout,
                ConnectTimeout,
                ReadTimeout,
                ConnectionError,
                TooManyRedirects,
            ) as exx:
                log.error("resource %r not available!", uri)

                # mark the url as blocked

                res_scheduler.block(uri, delay=30)

                log.error(
                    "[checkOtp] Error getting response from "
                    "Yubico Cloud Server (%r)",
                    uri,
                )

            except Exception as exx:
                log.error("unknown exception for uri %r!", uri)

                raise exx

        # ------------------------------------------------------------------ --

        # if we reach here, no resource has been availabel

        log.error("non of the resources %r available!", yubico_urls)

        raise AllResourcesUnavailable(
            "non of the resources %r available!" % yubico_urls
        )

    def _check_yubico_response(self, nonce, apiKey, rv):
        """
        parse and validate the yubico response

        :param nonce: validate against given nonce
        :param apikey: validate against our apiKey
        :param rv: yukico response

        :return: -1 or 1
        """

        m = re.search(r"\nstatus=(\w+)\r", rv)
        if not m:
            return -1

        result = m.group(1)
        if result != "OK":
            # possible results are listed here:
            # https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20
            log.warning("[checkOtp] failed with %r", result)
            return -1

        m = re.search(r"nonce=(\w+)\r", rv)
        if not m:
            return -1

        return_nonce = m.group(1)

        m = re.search(r"h=(.+)\r", rv)
        if not m:
            return -1

        return_hash = m.group(1)

        # check signature:
        elements = rv.split("\r")
        hash_elements = []
        for elem in elements:
            elem = elem.strip("\n")
            if elem and elem[:2] != "h=":
                hash_elements.append(elem)

        hash_input = "&".join(sorted(hash_elements))

        sec_obj = self._get_secret_object()

        h_digest = sec_obj.hmac_digest(
            data_input=hash_input.encode("utf-8"),
            bkey=binascii.a2b_base64(apiKey),
            hash_algo=sha1,
        )

        hashed_data = binascii.b2a_base64(h_digest)[:-1].decode()

        if hashed_data != return_hash:
            log.error(
                "[checkOtp] The hash of the return from the Yubico Cloud"
                " server does not match the data!"
            )
            return -1

        if nonce != return_nonce:
            log.error(
                "[checkOtp] The returned nonce does not match"
                " the sent nonce!"
            )
            return -1

        if result == "OK":
            return 1

        return -1


# eof
