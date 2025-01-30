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


""" """

import binascii
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse, urlsplit

from Cryptodome.Hash import SHA256 as SHA256

import linotp.lib.crypto
from linotp.lib.crypto.utils import check, createActivationCode, kdf2
from linotp.lib.ext.pbkdf2 import PBKDF2
from linotp.lib.reply import create_img
from linotp.tokens.ocra2token import OcraSuite

log = logging.getLogger(__name__)


class OcraOtp:
    def __init__(self, ocrapin=None):
        self.ocra = None
        self.bkey = None
        self.ocrapin = ocrapin
        self.activationkey = None
        self.sharedsecret = None
        self.ocrasuite = None
        self.serial = None
        self.counter = 0

    def init_1(self, response):
        """take the response of the first init to setup the OcraOtp"""

        jresp = json.loads(response.body)
        assert "detail" in jresp, response.body
        app_import = str(jresp.get("detail", {}).get("app_import"))
        self.sharedsecret = str(jresp.get("detail", {}).get("sharedsecret"))
        self.serial = str(jresp.get("detail", {}).get("serial"))

        # now parse the appurl for the ocrasuite
        uri = urlparse(app_import.replace("lseqr://", "http://"))
        qs = uri.query
        qdict = parse_qs(qs)

        ocrasuite = qdict.get("os", None)
        if ocrasuite is not None and len(ocrasuite) > 0:
            ocrasuite = ocrasuite[0]

        self.ocrasuite = ocrasuite

        return (self.ocrasuite, self.sharedsecret, self.serial)

    def check_signature(self, lseqr_url):
        # parse the url

        o = urlsplit(lseqr_url)
        # due to different  behaviour of urlsplit, we introduce here the
        # fallback for elder versions to use the path (o[2]) instead of the
        # o[3] (query)
        if o[3]:  # query
            qs = o[3]
        elif o[2]:  # path
            qs = o[2].lstrip("?")
        else:
            raise Exception("no query parameter defined!")

        params = parse_qs(qs)
        if "si" not in params:
            return None
        si = params["si"][0]
        data = lseqr_url.split("&si=")[0]

        if self.ocra is None:
            self._setup_()

        signature = self.ocra.signData(data.encode("utf-8"), key=self.bkey)
        if si.encode("utf-8") == signature:
            return True

        return False

    def init_2(self, response, activationKey):
        self.activationkey = activationKey

        jresp = json.loads(response.body)
        if "detail" in jresp:
            detail = jresp["detail"]
        else:
            detail = jresp["result"]["value"]["ocratoken"]

        assert detail, response.body

        self.transid = detail.get("transactionid", detail.get("transaction"))

        # now parse the appurl for challenge and nonce

        app_import = detail.get("app_import", detail.get("url"))
        uri = urlparse(app_import.replace("lseqr://", "http://"))
        qdict = parse_qs(uri.query)

        nonce = qdict.get("no", [])
        if nonce is not None and len(nonce) > 0:
            self.nonce = nonce[0]

        challenge = qdict.get("ch", [])
        if challenge:
            self.challenge = challenge[0]

        self.ocra = None
        self.bkey = None

        return (self.challenge, self.transid)

    def _setup_(self):
        if self.ocra is not None and self.bkey is not None:
            return

        key_len = 20
        if self.ocrasuite.find("-SHA256"):
            key_len = 32
        elif self.ocrasuite.find("-SHA512"):
            key_len = 64

        self.bkey = kdf2(
            self.sharedsecret, self.nonce, self.activationkey, len=key_len
        )
        self.ocra = OcraSuite(self.ocrasuite)

        self.counter = 0

        return

    def callcOtp(self, challenge=None, ocrapin=None, counter=-1):
        if self.ocra is None:
            self._setup_()

        if ocrapin is None:
            ocrapin = self.ocrapin

        if challenge is None:
            challenge = self.challenge
        if counter == -1:
            counter = self.counter

        param = {}
        param["C"] = counter
        param["Q"] = challenge
        param["P"] = ocrapin
        param["S"] = ""
        if self.ocra.T is not None:
            # Default value for G is 1M, i.e., time-step size is one minute and
            # the T represents the number of minutes since epoch time [UT].
            now = datetime.utcnow()
            stime = now.strftime("%s")
            itime = int(stime)
            param["T"] = itime

        data = self.ocra.combineData(**param)
        otp = self.ocra.compute(data, self.bkey)

        if counter == -1:
            self.counter += 1

        return otp
