# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
"""module for SecurityModules / devices like hsms"""
import logging
log = logging.getLogger(__name__)



class SecurityModule(object):

    def __init__(self, config=None):
        log.error("[__init__] This is the base class. You should implement this!")
        self.name = "SecurityModule"

    def isReady(self):
        fname = 'isReady'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)

    def setup_module(self, params):
        fname = 'setup_module'
        log.error("[%r] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)

    ''' base methods '''
    def random(self, len):
        fname = 'random'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)

    def encrypt(self, value, iv=None):
        fname = 'encrypt'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)

    def decrypt(self, value, iv=None):
        fname = 'decrypt'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)


    ''' higer level methods '''
    def encryptPassword(self, cryptPass):
        fname = 'decrypt'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)

    def encryptPin(self, cryptPin):
        fname = 'decrypt'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)


    def decryptPassword(self, cryptPass):
        fname = 'decrypt'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)

    def decryptPin(self, cryptPin):
        fname = 'decrypt'
        log.error("[%s] This is the base class. You should implement "
                  "the method : %s " % (self.name, fname))
        raise NotImplementedError("Should have been implemented %s"
                                   % fname)


#eof###########################################################################

