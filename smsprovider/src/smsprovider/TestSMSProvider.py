# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
""" This is the SMSClass to send SMS via HTTP Gateways
                This is a dummy class for testing
"""

import SMSProvider
from SMSProvider import getSMSProviderClass
from SMSProvider import ISMSProvider


import logging
log = logging.getLogger(__name__)


class TestSMSProvider(ISMSProvider):
    def __init__(self):
        self.config = {}

    '''
      submitMessage()
      - send out a message to a phone

    '''

    def _submitMessage(self, phone, message):
        return 'true' in message.lower()

    def getParameters(self, message, phone):
        return

    def loadConfig(self, configDict):
        self.config = configDict

