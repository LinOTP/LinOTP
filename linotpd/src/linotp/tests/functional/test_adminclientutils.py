# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


"""
used to do functional testing of the admin clientutils
"""

import logging
from linotp.tests import TestController
from linotputils.clientutils import linotpclient


log = logging.getLogger(__name__)

PROTOCOL = "http"
URL = "127.0.0.1:5001"
ADMIN = "bla"
ADMINPW = "foo"
CERT = ""
KEY = ""

class TestClientadmin(TestController):

    ### define Admins

    def _create_client(self):
        self.lotpc = linotpclient(PROTOCOL, URL , admin=ADMIN, adminpw=ADMINPW,)


    def test_01_show(self):
        '''
        list the tokens
        '''
        self._create_client()
        param = {}
        response = self.lotpc.listtoken(param)
        self.assertTrue(response['result']['status'], "Unexpected response: %r" % response)

