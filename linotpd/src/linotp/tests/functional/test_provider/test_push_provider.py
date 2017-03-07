# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

import os
import logging
import requests

from mock import patch

from linotp.tests import TestController
from linotp.provider.pushprovider.default_push_provider \
        import DefaultPushProvider


"""
    functional test for the DefaultPushProvider:

    - check the DefaultPushProvider functions

"""

VALID_REQUEST = 'You received an authentication request.'

log = logging.getLogger(__name__)


def mocked_http_request(HttpObject, *argparams, **kwparams):

    class Response:
        pass

    r = Response()

    r.status = TestPushProviderController.R_AUTH_STATUS
    r.text = TestPushProviderController.R_AUTH_DETAIL

    if r.status == 200:
        r.ok = True
        r.content = r.text
        return r

    r.ok = False
    r.reason = r.text

    return r


class TestPushProviderController(TestController):
    """
    test the push provider
    """

    R_AUTH_STATUS = 200
    R_AUTH_DETAIL = VALID_REQUEST

    def setUp(self):
        return

    def tearDown(self):
        self.delete_all_resolvers()
        super(TestPushProviderController, self).tearDown()

    def test_read_config(self):
        """
        test push provider configuration handling
        """

        configDict = {}
        push_prov = DefaultPushProvider()

        #
        # first test the valid configuration
        #

        configDict['Timeout'] = '30'
        configDict['access_certificate'] = os.path.join(self.fixture_path,
                                                        'cert.pem')

        configDict['push_url'] = "https://Notification.keyidentity.com/send"

        push_prov.loadConfig(configDict)

        #
        # verify server url check
        #

        with self.assertRaises(requests.exceptions.InvalidSchema):
            configDict['push_url'] = "hXXXs://proxy.keyidentity.com:8800/send"
            push_prov.loadConfig(configDict)

        #
        # restore configuration for push_url
        #

        configDict['push_url'] = "https://Notification.keyidentity.com/send"

        #
        # extended option: proxy
        #

        configDict['proxy'] = "https://proxy.keyidentity.com:8800/"
        push_prov.loadConfig(configDict)

        #
        # extended option: proxy with wrong url scheme
        #

        with self.assertRaises(requests.exceptions.InvalidSchema):
            configDict['proxy'] = "hXXXs://proxy.keyidentity.com:8800/"
            push_prov.loadConfig(configDict)

        # restore valid proxy url
        configDict['proxy'] = "https://proxy.keyidentity.com:8800/"

        #
        # valid extended timeout format
        #

        configDict['timeout'] = '3,10'
        push_prov.loadConfig(configDict)

        del configDict['timeout']

        #
        # invalid timeout format: "invalid literal for float()"
        #

        with self.assertRaises(ValueError):
            configDict['Timeout'] = '30s'
            push_prov.loadConfig(configDict)

        # timeout has a default and is not required
        del configDict['Timeout']

        #
        # non existing certificate file - should raise exception
        # 'required authenticating client cert could not be found'
        #

        with self.assertRaises(IOError):
            cert_file_name = os.path.join(self.fixture_path, 'non_exist.pem')
            configDict['access_certificate'] = cert_file_name
            push_prov.loadConfig(configDict)

        #
        # test if missing required parameters is detected
        #

        with self.assertRaises(KeyError):
            del configDict['access_certificate']
            push_prov.loadConfig(configDict)

        # restore access certificate parameter
        cert_file_name = os.path.join(self.fixture_path, 'cert.pem')
        configDict['access_certificate'] = cert_file_name

        # check if missing push_url is as well detected
        with self.assertRaises(KeyError):
            del configDict['push_url']
            push_prov.loadConfig(configDict)

        # restore required push_url
        configDict['push_url'] = "https://Notification.keyidentity.com/send"

        #
        # check if server cert is provided, the existance of directory or
        # file is made
        #

        server_cert_file_name = os.path.join(self.fixture_path, 'cert.pem')
        configDict['server_certificate'] = server_cert_file_name
        push_prov.loadConfig(configDict)

        with self.assertRaises(IOError):
            server_cert_file_name = '/abc/ssl/certs'
            configDict['server_certificate'] = server_cert_file_name
            push_prov.loadConfig(configDict)

        return

    @patch.object(requests.Session, 'post', mocked_http_request)
    def test_request(self):
        """
        do some mocking of a requests request
        """

        configDict = {}
        configDict['Timeout'] = '30'
        configDict['access_certificate'] = os.path.join(self.fixture_path,
                                                        'cert.pem')
        configDict['push_url'] = "https://notification.keyidentity.com/send"

        push_prov = DefaultPushProvider()
        push_prov.loadConfig(configDict)

        push_prov = DefaultPushProvider()
        push_prov.loadConfig(configDict)
        gda = ("apn.98c78e19e9842a1cfdeb887bf42142b615865b1ec513"
               "c31ea1a4f3222660435f")
        message = "Authentication request for user bla"

        # set the response status
        TestPushProviderController.R_AUTH_STATUS = 200

        # run the fake request
        status, response = push_prov.push_notification(message=message,
                                                       gda=gda)

        self.assertEquals(status, True)
        self.assertEquals(response, VALID_REQUEST)

        return
