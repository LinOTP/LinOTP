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
* implementation of the KeyIdentity VoiceProvider
"""

import logging

import requests

from linotp.provider import provider_registry
from linotp.provider.config_parsing import ConfigParsingMixin
from linotp.provider.voiceprovider import TwillioMixin

#
# set the default connection and request timeouts
#

DEFAULT_TIMEOUT = (3, 5)

log = logging.getLogger(__name__)


@provider_registry.class_entry("CustomVoiceProvider")
@provider_registry.class_entry("linotp.provider.CustomVoiceProvider")
@provider_registry.class_entry(
    "linotp.provider.voiceprovider.custom_voice_provider.CustomVoiceProvider"
)
class CustomVoiceProvider(ConfigParsingMixin, TwillioMixin):
    """
    Send a Voice notification through the Custom Voice Provider to the
    Voice Challenge Service. The CustomVoiceProvider allows to define all
    required config definitions directly and expects the following parameter:

    {
    "server_url": "https://vcs.*/v1/twilio/call"
    "access_certificate": "/etc/linotp/voice-license.pem",
    "server_certificate": "/etc/linotp/keyidentity-voice-ca-bundle.crt"
    'callerNumber': '+4989231234567'
    }

    Part of the config definition is as well the Voice Delivery Service
    configuration definition, whereby currently the twilio definition is the
    only supported one:

    'twilio': {
        'accountSid': 'ACf9095f540f0b090edbd239b99230a8ee',
        'authToken': '8f36aab7ca485b432500ce49c15280c5'
        'voice': 'alice',
        }

    """

    def __init__(self):
        """"""
        self.server_url = None
        self.client_cert = None
        self.server_cert = None
        self.proxy = None
        self.timeout = DEFAULT_TIMEOUT

        self.service_config = {}
        self.callerNumber = None

    def loadConfig(self, configDict):
        """
        Loads the configuration for this Voice notification provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in a linotp.cfg file)

        {
            "server_url":
                the voice provider target url,
            "access_certificate":
                the client certificate
            "server_certificate":
                server verification certificate
            "proxy": '
                the proxy url
            "timeout":
                the http timeout value

            "twillioConfig": {
                "accountSid":
                    the account identifier
                "authToken":
                    the authentication token
                "voice":
                    reader's voice - default is 'alice'
                "callerNumber":
                    the number of the originator
                }
        }
        """
        # ------------------------------------------------------------------ --

        # define the request calling endpoint and verify the url scheme

        if "server_url" not in configDict:
            msg = "missing the required server_url"
            raise KeyError(msg)

        self.voice_server_url = CustomVoiceProvider.load_server_url(configDict)

        # ------------------------------------------------------------------ --

        #
        # for authentication on the vcs we require a client certificate
        #

        self.client_cert = CustomVoiceProvider.load_client_cert(configDict)

        # ------------------------------------------------------------------ --

        #
        # default is no server verification, but if provided
        # it must be either a file or directory reference
        #

        self.server_cert = CustomVoiceProvider.load_server_cert(configDict)

        # ------------------------------------------------------------------ --

        # timeout could be a tuple of network timeout or connection timeout

        self.timeout = CustomVoiceProvider.load_timeout(configDict, DEFAULT_TIMEOUT)

        # ------------------------------------------------------------------ --

        #
        # we support proxy configuration, whereby here 'requests'
        # distinguishes between http and https proxies, which are provided
        # in a dicitionary to the request api
        #

        self.proxy = CustomVoiceProvider.load_proxy(configDict)

        # ------------------------------------------------------------------ --

        # load the voice message delivery service configuration

        delivery_service = configDict.get("twilioConfig")

        if not delivery_service:
            msg = "Missing delivery service configuration: twillioConfig"
            raise KeyError(msg)

        # prepare the twilio voice provider
        # . . . other voice services will follow here

        twilio_config = CustomVoiceProvider.load_twilio_definition(configDict)
        if twilio_config:
            self.service_config.update(twilio_config)

    def submitVoiceMessage(self, calleeNumber, messageTemplate, otp, locale):
        """
        Sends out the voice notification message.

        {
          'call':
            {
              'calleeNumber': '+4917012345678',
              'messageTemplate': 'Hi! Your otp is {otp}'
              'otp': '98018932'
              'locale': 'en',
            }
        }

        the other information is joined in the lower level of the http call

        :param calleeNumber: the destination phone number
        :param messageTemplate: the message text containing the placeholder for
                                the otp
        :param otp: the otp
        :param locale: the language of the voice reader

        :return: A tuple of success and result message
        """

        if not calleeNumber:
            msg = "Missing target number!"
            raise Exception(msg)

        if not messageTemplate:
            msg = "No message to submit!"
            raise Exception(msg)

        if "{otp}" not in messageTemplate:
            log.warning("Missing '{otp}' in messageTemplate: %r", messageTemplate)

        if not otp:
            msg = "Missing otp value!"
            raise Exception(msg)

        if not locale:
            locale = "en"

        # ----------------------------------------------------------------- --

        # combine the call parameters from request and configuration into
        # the json call document

        call = {
            "calleeNumber": calleeNumber,
            "messageTemplate": messageTemplate,
            "otp": otp,
            "locale": locale,
        }

        # add the voice delivery service (twilio) specific data

        call.update(self.service_config)

        # ----------------------------------------------------------------- --

        # run the request against the vcs

        return self._make_http_post_request_(json={"call": call})

    def _make_http_post_request_(self, json=None):
        """
        lower layer for the http post request to support json
        document submission

        :param json: json document for POST body

        :return: response and result tuple
        """

        # adjust HTTP header for submitting the json body

        headers = {"Content-type": "application/json", "Accept": "text/plain"}

        pparams = {}

        if self.timeout:
            pparams["timeout"] = self.timeout

        try:  # submit the POST request
            http_session = self._create_http_session_()

            response = http_session.post(
                self.voice_server_url, json=json, headers=headers, **pparams
            )

            result = response.reason if not response.ok else response.content

        finally:
            log.debug("leaving voice token provider")

        return response.ok, result

        # ------------------------------------------------------------------ --

    def _create_http_session_(self):
        """
        create the http session with certificates and proxy

        :return: the http session object
        """

        http_session = requests.Session()

        # -------------------------------------------------------------- --

        # add the proxy if defined

        if self.proxy:
            http_session.proxies.update(self.proxy)

        # -------------------------------------------------------------- --

        # add the client certificate if defined

        if self.client_cert:
            http_session.cert = self.client_cert

        # -------------------------------------------------------------- --

        # add the server cert to support the server verification if avail

        if self.server_cert is False:
            http_session.verify = False

        if self.server_cert:
            http_session.verify = self.server_cert

        return http_session

    def test_connection(self):
        """
        to test the connection, we just call the same endpoint without
        arguments (empty document), which will raise an error 400
        """
        status, response = self._make_http_post_request_(json={})

        if response == "Bad Request":
            return True, response

        return False, response


# eof
