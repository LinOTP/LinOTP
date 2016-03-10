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

""" the SMS Provider Interface """

from smsprovider.SMSProvider import ISMSProvider

import os
import logging

from linotp.lib.util import str2unicode

log = logging.getLogger(__name__)


class FileSMSProvider(ISMSProvider):
    def __init__(self):
        self.config = {}

    def getConfigDescription(self):
        """
        return a description of which config options are available
        """
        iface = {'file': ('the filename, where the phone and otp '
                          'values are to be stored.'),
                 'here': ('the base path for the text file'),
                 'MSISDN': ('normalize the phone numbers'),
                 }

        return iface

    def _submitMessage(self, phone, message):
        """
        write the message down to the given file

        :param phone: given phone number
        :param message: the provided message, containing the otp
        """
        ret = False

        filename = self.config.get('file', '')
        here = self.config.get('here', '')

        if here:
            filename = "%s%s%s" % (here, os.path.sep, filename)
        try:
            with open(filename, "w") as f:
                msg = u"%s:%s" % (str2unicode(phone), str2unicode(message))
                f.write(msg.encode('utf-8'))
            ret = True
        except Exception as exx:
            log.exception(exx)
            ret = False
        finally:
            return ret

    def loadConfig(self, configDict):
        self.config = configDict
