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
"""


import logging
from linotp.tests import TestController, url

log = logging.getLogger(__name__)

class TestOrphanedTokens(TestController):


    def test_httperror(self):

        param = { 'otpkey': 'AD8EABE235FC57C815B26CEF3709075580B44738',
                  'user': 'root', 'pin':'pin', 'serial':'T2', 'type':'spass', 'resConf':'def'
                 }

        response = self.app.get(url(controller='admin', action='init'), params=param)
        assert '"status": false,' in response


        param = { 'otpkey': 'AD8EABE235FC57C815B26CEF3709075580B44738',
                  'user': 'root', 'pin':'pin', 'serial':'T2', 'type':'spass', 'resConf':'def', 'httperror':'400'
                 }
        try:
            response = self.app.get(url(controller='admin', action='init'), params=param)
        except Exception as e:
            httperror = e.args[0]
            assert "400 Bad Request" in httperror


        param = { 'otpkey': 'AD8EABE235FC57C815B26CEF3709075580B44738',
                  'user': 'root', 'pin':'pin', 'serial':'T2', 'type':'spass', 'resConf':'def', 'httperror':''
                 }
        try:
            response = self.app.get(url(controller='admin', action='init'), params=param)
        except Exception as e:
            httperror = e.args[0]
            assert "500 Internal Server Error" in httperror

        return


