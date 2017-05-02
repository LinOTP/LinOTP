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
from linotp.tests import url
import threading

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


class DoRequest(threading.Thread):
    ''' the request thread'''

    def __init__(self, utest, rid=1, uri=None, params=None):
        '''
        initialize all settings of the request thread

        :param utest: method/function to be called
        :param rid: the request id
        :param uri: the request url object
        :param params: additional parmeters
        '''
        threading.Thread.__init__(self)

        self.utest = utest
        self.rid = rid
        self.uri = uri
        self.params = params

        self.response = None

    def run(self):
        '''
        run the request

        run the request until we recieve an valid response -
        background is, that we are making an authenticated request,
        which does a login and a redirect. The redirect though is sometimes
        ignored within the testing.
        The inidcation for a redirect is in our test setup, that we dont get
        a json resonse. In this case we do a retry until we have a valid
        response
        '''

        ok = False
        while not ok:
            response = self.utest.app.get(self.uri, params=self.params)
            self.response = response.body
            try:
                json.loads(self.response)
                ok = True
            except ValueError:
                ok = False

        return

    def status(self):
        '''
        retrieve the request result

        :return: the thread request result
        '''
        res = '"status": true,' in self.response
        return res

    def stat(self):
        '''
        retrieve the complete response
        '''
        return (self.rid, self.response)


class TestConfigController(TestController):
    """
    test for large Config entries
    """

    alphabeth = None

    def setUp(self):
        self.set_config_selftest()
        TestController.setUp(self)
        return

    def tearDown(self):
        self.set_config_selftest(unset=True)
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

    def test_wrapping_large_utf8_password_config(self):
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

    def test_delete_of_previous_continous(self):
        """
        store concurrently multiple different config entries at once

        to deal correctly with multiple joined config entries on every store
        request all potential continous config entries are deleted upfront, as
        the updated entry might be shorter than the previous one.
        So we query the database for such entries and mark them for delete.
        This algorithm works fine for standard sql databases.

        But there is a bug within the mysql query processing, which does not
        check upfront, if there is a to be deleted entry at all. If there is
        no entry thus the mysql query processor creates a lock for the table
        and when there is no entry, forgets to remove the lock, which results
        in a deadlock in case of two concurrent requests

        """

        multiple_entries = [{
            'PassOnUserNoToken': 'False',
            'client.FORWARDED': 'False',
            'AutoResync': 'False',
            'splitAtSign': 'False',
            }, {
            'certificates.use_system_certificates': 'False',
            'user_lookup_cache.enabled': 'True',
            'selfservice.realmbox': 'False',
            'resolver_lookup_cache.enabled': 'True',
            }, {
            'allowSamlAttributes': 'False',
            'FailCounterIncOnFalsePin': 'True',
            'PassOnUserNotFound': 'False',
            }, {
            'PrependPin': 'True',
            'client.X_FORWARDED_FOR': 'False'}]

        check_results = []
        numthreads = len(multiple_entries)

        params = {}
        for tid in range(numthreads):
            params[tid] = multiple_entries[tid]

        uri = url(controller='system', action='setConfig')

        for tid in range(numthreads):
            param = params.get(tid)
            current = DoRequest(self, rid=tid, uri=uri, params=param)
            check_results.append(current)
            current.start()

        # wait till all threads are completed
        for req in check_results:
            req.join()

        # now check in the config if all keys are there
        msg = "Deadlock found when trying to get lock"
        for check_result in check_results:
            try:
                jresp = json.loads(check_result.response)
                error_message = jresp.get('result', {}).get(
                                          'error', {}).get(
                                          'message', '')
                self.assertNotIn(msg, error_message, check_result.response)

            except (ValueError, TypeError) as _exx:
                log.info("Failed to set Config %r", check_result.response)

        return

#
