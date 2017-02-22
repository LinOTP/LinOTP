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


"""
Test the handling of large config entries
"""

import base64
import binascii
import random

import os
import json
import logging
from linotp.tests import TestController

#
# helper method to create random data
#


def create_unicode_alphabet():
    try:
        get_char = unichr
    except NameError:
        get_char = chr

    # Update this to include code point ranges to be sampled
    include_ranges = [
        (0x0021, 0x0021),
        (0x0023, 0x0026),
        (0x0028, 0x007E),
        (0x00A1, 0x00AC),
        (0x00AE, 0x00FF),
        (0x0100, 0x017F),
        (0x0180, 0x024F),
        (0x2C60, 0x2C7F),
        (0x16A0, 0x16F0),
        (0x0370, 0x0377),
        (0x037A, 0x037E),
        (0x0384, 0x038A),
        (0x038C, 0x038C),
    ]

    alphabeth = []
    for current_range in include_ranges:
        for code_point in range(current_range[0], current_range[1] + 1):
            alphabeth.append(get_char(code_point))

    return alphabeth


def create_long_unicode(alphabeth, length):
    """
    create a string of length with unicode characters
    from a given alphabeth

    :param alphabet: list of unicode characters to select from
    :param length: the number of uchars in the result string

    :return: result string with random sequence of unicode chars
    """

    res = []
    while len(res) < length:
        uchar = random.choice(alphabeth)
        res.append(uchar)

    return ''.join(res)


def create_long_entries(length):
    """
    create large data by using the random device

    :param length: the amount of random bytes
    :return: binary data of length
    """
    bin_data = os.urandom(length)
    return bin_data


log = logging.getLogger(__name__)


class TestConfigController(TestController):
    """
    test for large Config entries
    """

    alphabeth = None

    def setUp(self):
        TestController.setUp(self)
        return

    def tearDown(self):
        TestController.tearDown(self)


#
# the long config entry test
#

    def test_random_large_base64_config(self):
        '''
        test long config entries with base64 data with many split entries

        config entry max length is 2000 -
        entry should be split up into 40 parts
        '''
        for i in xrange(1, 10):

            length = 1000 * i + random.randint(0, 1000)

            config_data = base64.b64encode(create_long_entries(length))

            config_entry = 'longBase64ConfigEntry%d' % i
            param = {config_entry: config_data}
            response = self.make_system_request('setConfig', params=param)

            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            self.assertEqual(config_data, data, 'error while comparing data')

        return

    def test_random_large_hexlify_config(self):
        '''
        test long config entries with hexlified data with many split entries

        config entry max length is 2000 -
        entry should be split up into 40 parts
        '''
        for i in xrange(1, 10):

            length = 1000 * i + random.randint(0, 1000)

            config_data = binascii.hexlify(create_long_entries(length))

            config_entry = 'longHexConfigEntry%d' % i
            param = {config_entry: config_data}
            response = self.make_system_request('setConfig', params=param)

            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            self.assertEqual(config_data, data, 'error while comparing data')

        return

    def test_random_large_UFT8_config(self):
        '''
        test long config entries with unicode chars that will be converted to utf-8

        config entry max length is 2000 -
        entry should be split up into 40 parts
        '''

        alphabeth = create_unicode_alphabet()

        for i in xrange(1, 10):

            length = 1000 * i + random.randint(0, 1000)

            config_entry = 'longUnicodeConfigEntry%d' % i
            config_data = create_long_unicode(alphabeth, length)
            u8_config_data = config_data.encode('utf-8')

            param = {config_entry: u8_config_data}
            response = self.make_system_request('setConfig', params=param)

            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            if config_data != data:
                it = 0
                while config_data[it] == data[it]:
                    if it >= min(len(config_data), len(data)):
                        break
                    it += 1

                self.assertEqual(config_data, data,
                                 'error while comparing data: %r  %r' %
                                 (config_data[it - 3:it + 1],
                                  data[it - 3:it + 1]))

            if len(config_data) != len(data):
                self.assertEqual(config_data, data,
                                 'error while comparing length: %r  %r' %
                                 (config_data[len(data):],
                                  data[len(config_data):]))

            self.assertEqual(config_data, data, 'error while comparing data')

        return

    def test_UFT8_alphabeth_config(self):
        '''
        test long config entries with all unicode chars

        config entry max length is 2000 -
        so we check the correct wrapping from 1980 to 2020
        '''

        alphabeth = create_unicode_alphabet()
        config_data_base = base64.b64encode(create_long_entries(1990))

        chunk_len = 2000
        i = -1
        pos = 0
        for pos in xrange(0, len(alphabeth), chunk_len):
            i = i + 1
            config_data_array = alphabeth[pos:pos + chunk_len]
            config_data = config_data_base + ''.join(config_data_array)
            u8_config_data = config_data.encode('utf-8')

            config_entry = 'longUnicodeConfigEntry%d' % i
            param = {config_entry: u8_config_data}
            response = self.make_system_request('setConfig', params=param)
            self.assertTrue('"status": true' in response, response)

            # error occures on update read, so we write a second time
            # to update this entry
            response = self.make_system_request('setConfig', params=param)
            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            if config_data != data:
                it = 0
                while config_data[it] == data[it]:
                    if it >= min(len(config_data), len(data)):
                        break
                    it += 1

                self.assertEqual(config_data, data,
                                 'error while comparing data: %r  %r' %
                                 (config_data[it - 3:it + 1],
                                  data[it - 3:it + 1]))

            if len(config_data) != len(data):
                self.assertEqual(config_data, data,
                                 'error while comparing length: %r  %r' %
                                 (config_data[len(data):],
                                  data[len(config_data):]))

            self.assertEqual(config_data, data, 'error while comparing data')

        return

    def test_wrapping_large_utf8_config(self):
        '''
        test long config entries with utf8 chars on split boundary

        config entry max length is 2000 -
        so we check the correct wrapping from 1980 to 2020
        '''

        alphabeth = create_unicode_alphabet()

        for i in xrange(1, 40):

            length = 1980 + i

            config_entry = 'longUtf8ConfigEntry%d' % i
            config_data = create_long_unicode(alphabeth, length)
            u8_config_data = config_data.encode('utf-8')

            param = {config_entry: u8_config_data}
            response = self.make_system_request('setConfig', params=param)
            self.assertTrue('"status": true' in response, response)

            # on the second setConfig an update is made, which is the read
            # of the broken utf-8 string and will fail
            param = {config_entry: u8_config_data}
            response = self.make_system_request('setConfig', params=param)
            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            if config_data != data:
                it = 0
                while config_data[it] == data[it]:
                    if it >= min(len(config_data), len(data)):
                        break
                    it += 1

                self.assertEqual(config_data, data,
                                 'error while comparing data: %r  %r' %
                                 (config_data[it - 3:it + 1],
                                  data[it - 3:it + 1]))

            if len(config_data) != len(data):
                self.assertEqual(config_data, data,
                                 'error while comparing length: %r  %r' %
                                 (config_data[len(data):],
                                  data[len(config_data):]))

            self.assertEqual(config_data, data, 'error while comparing data')

        return

    def test_0000_wrapping_large_utf8_password_config(self):
        '''
        test long config entries with utf8 chars on split boundary

        config entry max length is 2000 -
        so we check the correct wrapping from 1980 to 2020
        '''

        alphabeth = create_unicode_alphabet()

        for i in xrange(1, 40):

            length = 1980 + i

            config_entry = 'longUtf8ConfigEntry%d' % i
            config_data = create_long_unicode(alphabeth, length)
            u8_config_data = config_data.encode('utf-8')

            # set as type password
            param = {
                config_entry: u8_config_data,
                config_entry + '.type': 'password'}

            response = self.make_system_request('setConfig', params=param)
            self.assertTrue('"status": true' in response, response)

            # on the second setConfig an update is made, which is the read
            # of the broken utf-8 string and will fail
            param = {
                config_entry: u8_config_data,
                config_entry + '.type': 'password'}

            response = self.make_system_request('setConfig', params=param)
            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            # we can't compare the result, as it is the encrypted data
            self.assertNotEqual(data, config_data, response)

        return

    def test_wrapping_large_hexlify_config(self):
        '''
        test long config entries with hexlified chars on split boundary

        config entry max length is 2000 -
        so we check the correct wrapping from 1980 to 2020
        '''

        for i in xrange(1, 40):

            length = 1980 + i

            config_entry = 'longHexlifyConfigEntry%d' % i
            config_data = binascii.hexlify(create_long_entries(length))
            param = {config_entry: config_data}
            response = self.make_system_request('setConfig', params=param)

            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            if config_data != data:
                it = 0
                while config_data[it] == data[it]:
                    if it >= min(len(config_data), len(data)):
                        break
                    it += 1

                self.assertEqual(config_data, data,
                                 'error while comparing data: %r  %r' %
                                 (config_data[it - 3:it + 1],
                                  data[it - 3:it + 1]))

            if len(config_data) != len(data):
                self.assertEqual(config_data, data,
                                 'error while comparing length: %r  %r' %
                                 (config_data[len(data):],
                                  data[len(config_data):]))

            self.assertEqual(config_data, data, 'error while comparing data')

        return

    def test_wrapping_large_base64_config(self):
        '''
        test long config entries with base64 chars on split boundary

        config entry max length is 2000 -
        so we check the correct wrapping from 1980 to 2020
        '''

        for i in xrange(1, 40):

            length = 1980 + i

            config_entry = 'longB64ConfigEntry%d' % i
            config_data = base64.b64encode(create_long_entries(length))

            param = {config_entry: config_data}
            response = self.make_system_request('setConfig', params=param)

            self.assertTrue('"status": true' in response, response)

            param = {'key': config_entry}
            response = self.make_system_request('getConfig', params=param)
            jresp = json.loads(response.body)

            entry_name = "getConfig %s" % config_entry
            data = jresp.get('result', {}).get('value', {}).get(entry_name)

            if config_data != data:
                it = 0
                while config_data[it] == data[it]:
                    if it >= min(len(config_data), len(data)):
                        break
                    it += 1

                self.assertEqual(config_data, data,
                                 'error while comparing data: %r  %r' %
                                 (config_data[it - 3:it + 1],
                                  data[it - 3:it + 1]))

            if len(config_data) != len(data):
                self.assertEqual(config_data, data,
                                 'error while comparing length: %r  %r' %
                                 (config_data[len(data):],
                                  data[len(config_data):]))

            self.assertEqual(config_data, data, 'error while comparing data')

        return

#
