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
"""This is the SMSClass to send SMS via HTTP Post Rest Interface Gateways"""


from linotp.provider.smsprovider import ISMSProvider
from linotp.provider import provider_registry
from linotp.provider import ProviderNotAvailable

import requests
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth

import logging
import os

log = logging.getLogger(__name__)


@provider_registry.class_entry('RestSMSProvider')
@provider_registry.class_entry('linotp.provider.smsprovider.RestSMSProvider')
@provider_registry.class_entry('smsprovider.RestSMSProvider.RestSMSProvider')
@provider_registry.class_entry('smsprovider.RestSMSProvider')
class RestSMSProvider(ISMSProvider):

    def __init__(self):
        self.config = {}
        self.client_cert = None
        self.server_cert = None

    def loadConfig(self, configDict):

        if not configDict:
            raise Exception('missing configuration')

        self.config = configDict

        self.username = configDict.get('USERNAME', None)
        self.password = configDict.get('PASSWORD', None)

        # proxy defintion must be in the following format:
        #
        #    . . .
        #    PROXY : {
        #        "http": "http://10.10.1.10:3128",
        #        "https": "http://10.10.1.10:1080",
        #    }
        #    . . .
        #    but we can as well provide Proxy via socks:
        #
        #    PROXY = {
        #        'http': 'socks5://user:pass@host:port',
        #        'https': 'socks5://user:pass@host:port'
        #    }
        #

        self.proxy = configDict.get('PROXY', None)

        self.auth_type = configDict.get('AUTHENTICATION', 'BASIC').lower()
        if self.auth_type not in ['basic', 'digest']:
            raise Exception("no valid Authentication type provided")

        # support for multiple urls

        self.url_config = configDict['URL']
        self.urls = [x.strip() for x in self.url_config.split(',')]

        # ------------------------------------------------------------------ --

        # timeout (float or tuple) -- (optional)
        # How many seconds to wait for the server to send data before giving
        # up, as a float, or a (connect timeout, read timeout) tuple.

        #!!! we set the timeout by default so that linotp wont block

        timeout = configDict.get("TIMEOUT", (3, 30))
        if isinstance(timeout, str):
            if ',' in timeout:
                con_timeout, read_timeout = timeout.rpartition(',')
                self.timeout = (float(con_timeout), float(read_timeout))
            else:
                self.timeout = float(timeout)
        else:
            self.timeout = timeout

        # ------------------------------------------------------------------ --

        # parameter is our json payload, which will provide the
        # keys where the phone and the message is replaced within

        self.payload = configDict['PAYLOAD']
        self.headers = configDict.get('HEADERS', {})
        self.sms_text_key = configDict['SMS_TEXT_KEY']
        self.sms_phone_key = configDict["SMS_PHONENUMBER_KEY"]

        self.client_cert = configDict.get("CLIENT_CERTIFICATE_FILE")
        self.server_cert = configDict.get("SERVER_CERTIFICATE")

    @staticmethod
    def _apply_phone_template(phone, sms_phone_template=None):
        """
        replace the phone number in the template

        :param phone: the target phone number
        :param sms_phone_template: string or list - template which contains
                                   the template string <phone> which is
                                   replaced
        :return: the phone number replaced in the template if template is given
        """

        # if the template is a simple string, we do a simple replace

        if isinstance(sms_phone_template, str):
            if sms_phone_template and '<phone>' in sms_phone_template:
                return sms_phone_template.replace('<phone>', phone)

        # if the template is a list, we replace text items
        # while others are preserved

        if isinstance(sms_phone_template, list):

            sms_phone = []
            for phone_tmpl in sms_phone_template:
                if (isinstance(phone_tmpl, str) and
                        '<phone>' in phone_tmpl):
                    sms_phone.append(phone_tmpl.replace('<phone>', phone))
                else:
                    sms_phone.append(phone_tmpl)
            return sms_phone

        # in any other case we do no replacement

        return phone

    def _submitMessage(self, phone, message):
        '''
        send out a message to a phone via an http sms connector
        :param phone: the phone number
        :param message: the message to submit to the phone
        '''

        log.debug("[submitMessage] submitting message "
                  "%s to %s" % (message, phone))

        pparams = {}

        # ----------------------------------------------------------------- --

        # care for the authentication

        if self.auth_type == 'basic':
            auth_method = HTTPBasicAuth

        elif self.auth_type == 'digest':
            auth_method = HTTPDigestAuth

        else:
            auth_method = None

        if self.username and auth_method:
            pparams['auth'] = auth_method(username=self.username,
                                          password=self.password)

        # ----------------------------------------------------------------- --

        # fill in the data into the payload

        json_body = {}
        json_body.update(self.payload)

        sms_message = json_body[self.sms_text_key]
        if sms_message and '<message>' in sms_message:
            sms_message = sms_message.replace('<message>', message)
        else:
            sms_message = message
        json_body[self.sms_text_key] = sms_message

        # ----------------------------------------------------------------- --

        # care for the phone number
        # do some phone number normalisation if MSISDN parameter is provided

        # prepare the phone number
        msisdn = 'true' in ("%r" % self.config.get('MSISDN', "false")).lower()
        if msisdn:
            phone = self._get_msisdn_phonenumber(phone)

        # ------------------------------------------------------------------ --

        # replace the phone if there is a given template for it

        sms_phone = self._apply_phone_template(phone,
                                               json_body.get(self.sms_phone_key))

        json_body[self.sms_phone_key] = sms_phone

        # ----------------------------------------------------------------- --

        # care for connection timeout

        if self.timeout:
            pparams['timeout'] = self.timeout

        # -------------------------------------------------------------- --

        # setup http headers

        # submitting the json body requires the correct HTTP headers
        # with contenttype declaration:

        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json'}

        if self.headers:
            headers.update(self.headers)

        http_session = requests.Session()

        # -------------------------------------------------------------- --

        # support for proxies

        if self.proxy:
            http_session.proxies.update(self.proxy)

        # ------------------------------------------------------------- --

        # client certificate -
        # we check if the client certificate exists, which is
        # referenced as a filename

        if self.client_cert and os.path.isfile(self.client_cert):
            http_session.cert = self.client_cert

        # ------------------------------------------------------------- --

        # server certificate

        server_cert = self.server_cert
        if server_cert is not None:
            # Session.post() doesn't like unicode values in Session.verify
            if isinstance(server_cert, str):
                server_cert = server_cert.encode('utf-8')

            http_session.verify = server_cert

        # ------------------------------------------------------------- --

        retry = 3

        while retry > 0:
            try:
                log.debug("Request Header: %r", headers)
                log.debug("Request Content: %r", json_body)
                response = http_session.post(self.urls[0],
                                             json=json_body,
                                             headers=headers,
                                             **pparams)

                if response.ok:
                    log.info("RestSMSProvider request success!")
                    log.debug("Response Headers: %r", response.headers)
                    log.debug("Response Content: %r", response.content)
                    return True

                log.info("RestSMSProvider request failed: %r", response.reason)
                return False

            except requests.exceptions.Timeout as exc:
                log.exception("RestSMSProvider timed out %r" % exc)
                retry -= 1
                if retry <= 0:
                    raise ProviderNotAvailable(
                        "RestSMSProvider timed out %r" % exc)

            except Exception as exc:
                log.exception("RestSMSProvider %r" % exc)
                retry = 0
                raise Exception("Failed to send SMS. %s" % str(exc))


##eof##########################################################################
