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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

import base64
import unittest
from linotp.lib.user import getUserFromRequest


class TestgetUserFromRequest(unittest.TestCase):
    class Request(object):
        def __init__(self, environ):
            self.params = ''
            self.environ = environ

    login = 'Hans Wurst'
    password = 'Enemenemuh'

    def run_and_assert(self, request):
        authentification = getUserFromRequest(request)
        self.assertEqual(authentification['login'], self.login,
                         'Input was: %r' % request.environ)
        return authentification

    def test_remote_authentification(self):
        request = self.Request({'REMOTE_USER': self.login})
        self.run_and_assert(request)

    def test_basic_authentification(self):
        basicstring = "Basic %s" % base64.b64encode(
            self.login + ':' + self.password)
        request = self.Request({'HTTP_AUTHORIZATION': basicstring})
        self.run_and_assert(request)

    def test_digest_authentifictaion(self):
        digest = "Digest username=%s, Digest Password=Enemenemuh" % self.login
        request = self.Request({'HTTP_AUTHORIZATION': digest})
        authentification = self.run_and_assert(request)
        self.assertEqual(authentification['Digest Password'], self.password,
                         'Input was: %r' % request.environ)

    def test_SSL_CLIENT_authentifictaion(self):
        request = self.Request({'SSL_CLIENT_S_DN_CN': self.login})
        self.run_and_assert(request)

    def test_empty_auth(self):
        request = self.Request({})
        authentification = getUserFromRequest(request)
        self.assertEqual(authentification['login'], '', 'Input was empty')
