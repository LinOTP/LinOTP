# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP smsprovider.
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
"""This is the SMSClass to send SMS via HTTP Gateways"""

import logging
import re
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from linotp.lib.type_utils import parse_timeout
from linotp.provider import ProviderNotAvailable, provider_registry
from linotp.provider.config_parsing import ConfigParsingMixin
from linotp.provider.smsprovider import ISMSProvider

log = logging.getLogger(__name__)


@provider_registry.class_entry("HttpSMSProvider")
@provider_registry.class_entry("linotp.provider.smsprovider.HttpSMSProvider")
@provider_registry.class_entry("smsprovider.HttpSMSProvider.HttpSMSProvider")
@provider_registry.class_entry("smsprovider.HttpSMSProvider")
class HttpSMSProvider(ISMSProvider, ConfigParsingMixin):
    def __init__(self):
        self.config = {}

    def _submitMessage(self, phone, message):
        """
        send out a message to a phone via an http sms connector
        :param phone: the phone number
        :param message: the message to submit to the phone
        """
        url = self.config.get("URL", None)
        if url is None:
            return

        log.debug(
            "[submitMessage] submitting message %s to %s", message, phone
        )

        method = self.config.get("HTTP_Method", "POST")

        log.debug("[submitMessage] by method %s", method)
        parameter = self.getParameters(message, phone)

        log.debug("[submitMessage] Now doing the Request")

        # ------------------------------------------------------------------ --

        # care for the authentication

        username = self.config.get("USERNAME", None)
        password = self.config.get("PASSWORD", None)

        # there might be the basic authentication in the request url
        # like http://user:passw@hostname:port/path

        if password is None and username is None:
            parsed_url = urlparse(url)
            if "@" in parsed_url[1]:
                puser, _server = parsed_url[1].split("@")
                username, password = puser.split(":")

        # ------------------------------------------------------------------ --

        # make the http request

        try:

            return self.request(url, parameter, username, password, method)

        except Exception as exx:
            log.warning("Failed to access the HTTP SMS Service %r", exx)
            raise exx

        return False

    def getParameters(self, message, phone):

        urldata = {}

        # transfer the phone key
        phoneKey = self.config.get("SMS_PHONENUMBER_KEY", "phone")
        urldata[phoneKey] = phone
        log.debug("[getParameters] urldata: %s", urldata)

        # transfer the sms key
        messageKey = self.config.get("SMS_TEXT_KEY", "sms")
        urldata[messageKey] = message
        log.debug("[getParameters] urldata: %s", urldata)

        params = self.config.get("PARAMETER", {})
        urldata.update(params)

        log.debug("[getParameters] urldata: %s", urldata)

        return urldata

    def _check_success(self, reply):
        """
        Check the success according to the reply

        if RETURN_SUCCESS_REGEX, RETURN_SUCCES,
            RETURN_FAIL_REGEX or RETURN_FAIL is defined
        :param reply: the reply from the http request

        :return: True or raises an Exception
        """

        log.debug("[_check_success] entering with config %r", self.config)
        log.debug("[_check_success] entering with reply %r", reply)

        if "RETURN_SUCCESS_REGEX" in self.config:
            ret = re.search(self.config["RETURN_SUCCESS_REGEX"], reply)
            if ret is not None:
                log.debug("[_check_success] sending SMS success")
            else:
                log.warning(
                    "[_check_success] failed to send SMS. "
                    "Reply does not match the RETURN_SUCCESS_REGEX "
                    "definition"
                )
                raise Exception(
                    "We received a none success reply from the SMS Gateway."
                )

        elif "RETURN_FAIL_REGEX" in self.config:
            ret = re.search(self.config["RETURN_FAIL_REGEX"], reply)
            if ret is not None:
                log.warning("[_check_success] sending SMS fail")
                raise Exception(
                    "We received a predefined error from the SMS Gateway."
                )
            else:
                log.debug(
                    "[_check_success] sending sms success full. "
                    "The reply does not match the RETURN_FAIL_REGEX "
                    "definition"
                )

        elif "RETURN_SUCCESS" in self.config:
            success = self.config.get("RETURN_SUCCESS")
            log.debug("[_check_success] success: %r", success)
            if reply[: len(success)] == success:
                log.debug("[_check_success] sending SMS success")
            else:
                log.warning(
                    "[_check_success] failed to send SMS. Reply does "
                    "not match the RETURN_SUCCESS definition"
                )
                raise Exception(
                    "We received a none success reply from the SMS Gateway."
                )

        elif "RETURN_FAIL" in self.config:
            fail = self.config.get("RETURN_FAIL")
            log.debug("[_check_success] fail: %r", fail)
            if reply[: len(fail)] == fail:
                log.warning("[_check_success] sending SMS fail")
                raise Exception(
                    "We received a predefined error from the SMS Gateway."
                )
            else:
                log.debug(
                    "[_check_success] sending sms success full. "
                    "The reply does not match the RETURN_FAIL "
                    "definition"
                )
        return True

    def request(
        self, url, parameter, username=None, password=None, method="GET"
    ):

        try:
            pparams = {}

            pparams["timeout"] = HttpSMSProvider.DEFAULT_TIMEOUT
            if "timeout" in self.config and self.config["timeout"]:
                pparams["timeout"] = parse_timeout(self.config["timeout"])

            if "PROXY" in self.config and self.config["PROXY"]:

                if isinstance(self.config["PROXY"], str):
                    proxy_defintion = {
                        "http": self.config["PROXY"],
                        "https": self.config["PROXY"],
                    }

                elif isinstance(self.config["PROXY"], dict):
                    proxy_defintion = self.config["PROXY"]

                pparams["proxies"] = proxy_defintion

            if username and password is not None:
                auth = None
                auth_type = (
                    self.config.get("AUTH_TYPE", "basic").lower().strip()
                )

                if auth_type == "basic":
                    auth = HTTPBasicAuth(username, password)

                if auth_type == "digest":
                    auth = HTTPDigestAuth(username, password)

                if auth:
                    pparams["auth"] = auth

            # --------------------------------------------------------------

            # set server certificate validation policy

            server_certificate = self.load_server_cert(
                self.config, server_cert_key="SERVER_CERTIFICATE"
            )

            if server_certificate is False:
                pparams["verify"] = False

            if server_certificate:
                pparams["verify"] = server_certificate

            # -------------------------------------------------------------- --

            # finally execute the request

            if method == "GET":
                response = requests.get(url, params=parameter, **pparams)
            else:
                response = requests.post(url, data=parameter, **pparams)

            reply = response.text
            # some providers like clickatell have no response.status!
            log.debug("HttpSMSProvider >>%r...%r<<", reply[:20], reply[-20:])
            ret = self._check_success(reply)

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.TooManyRedirects,
        ) as exc:

            log.error("HttpSMSProvider timed out")
            raise ProviderNotAvailable(
                "Failed to send SMS - timed out %r" % exc
            )

        except Exception as exc:
            log.error("HttpSMSProvider %r", exc)
            raise Exception("Failed to send SMS. %r" % exc)

        return ret

    def loadConfig(self, configDict):

        if not configDict:
            raise Exception("missing configuration")

        self.config = configDict


##eof##########################################################################
