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
Functional special test are tests, which require a remote service,
either an linotp server, an radius server or a http sms reciever

The TestSpecialController gathers some of these common methods.

"""
import urllib
import httplib2
import os

from linotp.tests import TestController

DEFAULT_NOSE_CONFIG = {
    'radius': {
        'authport': '18012',
        'acctport': '18013',
        },
    'paster': {
        'port': '5001',
        }
    }
try:
    from testconfig import config as nose_config
except ImportError as exc:
    print "You need to install nose-testconfig. Will use default values."
    nose_config = None


import logging
log = logging.getLogger(__name__)


class TestSpecialController(TestController):

    radius_authport = DEFAULT_NOSE_CONFIG['radius']['authport']
    radius_acctport = DEFAULT_NOSE_CONFIG['radius']['acctport']
    paster_port = DEFAULT_NOSE_CONFIG['paster']['port']

    @classmethod
    def setup_class(cls):
        if nose_config and 'radius' in nose_config:
            cls.radius_authport = nose_config['radius']['authport']
            cls.radius_acctport = nose_config['radius']['acctport']

        if nose_config and 'paster' in nose_config:
            cls.paster_port = nose_config['paster']['port']

        TestController.setup_class()

    @classmethod
    def teardown_class(cls):
        TestController.teardown_class()

    @staticmethod
    def do_http_request(remoteServer, params=None, headers=None, cookies=None,
                        method='POST'):

            request_url = "%s" % (remoteServer)

            if not params:
                params = {}
            data = urllib.urlencode(params)

            # predefine the submit and receive headers, but allow the overwrite
            r_headers = {"Content-type": "application/x-www-form-urlencoded",
                         "Accept": "text/plain"}
            if headers:
                r_headers.update(headers)

            if cookies:
                cooking = []
                for key, value in cookies.items():
                    cooking.append('%s=%s' % (key, value))
                r_headers['Cookie'] = ";".join(cooking)

            # submit the request
            http = httplib2.Http()
            (_resp, content) = http.request(request_url,
                                           method=method,
                                           body=data,
                                           headers=r_headers)
            return content

    @staticmethod
    def check_for_process(service):
        """
        simple, limited check for an service
        """
        result = False
        import subprocess
        p = subprocess.Popen(["ps", "-a"], stdout=subprocess.PIPE)
        out, _err = p.communicate()
        if service in out:
            result = True
        return result

    @staticmethod
    def check_for_port(port):
        """
        check for a service behind a port
        """
        result = False
        import subprocess
        p = subprocess.Popen(["lsof", "-t", "-i:%s" % port],
                             stdout=subprocess.PIPE)
        out, _err = p.communicate()
        if len(out) > 0:
            result = True
        return result

    @staticmethod
    def start_radius_server(radius_authport, radius_acctport):
        """
        Start the dummy radius server

        We need to start the radius server for every test, since every test
        instatiates a new TestClass and thus the radius server process will
        not be accessable outside of a test anymore
        """
        import subprocess
        try:
            radius_server_file = os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                '..',
                'tools',
                'dummy_radius_server.py',
                )
            dictionary_file = os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                '..',
                '..',
                '..',
                'config',
                'dictionary',
                )
            proc = subprocess.Popen(
                [
                    radius_server_file,
                    "--dict",
                    dictionary_file,
                    "--authport",
                    radius_authport,
                    "--acctport",
                    radius_acctport,
                    ]
                )
        except Exception as exx:
            raise exx
        assert proc is not None

        return proc

    @staticmethod
    def stop_radius_server(proc):
        '''
        stopping the dummy radius server
        '''
        if proc:
            r = proc.kill()
            log.debug(r)

        return

