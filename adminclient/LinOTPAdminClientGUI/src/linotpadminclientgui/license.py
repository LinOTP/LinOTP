#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
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
 get and display the linotp support license
"""


from linotpadminclientcli.clientutils import LinOTPClientError
import linotpadminclientcli.clientutils as clientutils


import base64
import hashlib
import logging
import logging.handlers

class licenseclient(object):

  def __init__(self, param):
    self.lines = [ '' ]
    self.licDict = {}
    if 'license' in param:
        self.setlicense(param['license'])
    if 'logging' in param:
        self.logging = True
        self.handler = logging.handlers.RotatingFileHandler(
            param['logging']['LOG_FILENAME'],
            maxBytes=param['logging']['LOG_SIZE'],
            backupCount=param['logging']['LOG_COUNT'])
        self.formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s]:%(message)s")
        self.handler.setFormatter(self.formatter)
        self.log = logging.getLogger("LinOTP license")
        self.log.setLevel(param['logging']['LOG_LEVEL'])
        self.log.addHandler(self.handler)
    else:
        self.logging = False

    self.public = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqgA4ium1T+0UafBjenx
Dclj79Nj/g55iA+hH8dsP/rIMLjwe8kimikhhXqkTKz1qHQvBF00DLy3L/aGbnKk
x4//EcqdcODP6lmazWSfkuy0MNkPBki3C5h9IlSY2qTrZGlup5NcRO2KK7G5iQZS
7r0zzQlN1mFNiZmob4rLYdNkcFOz52/yBm8QV//dKvvmCNOuHJJl8zAT7R0Oe1M+
BbKBUlx/8GqnwpftJjOmH3qQUjQistt0XJvAOBk2G+jfLMknQmK+KmfzrCxkY1t7
+YrjBwJgMQhdAD/n4sjuI21BYx9iX5OpTiO+K+F0UC6IHCeqHexZObTpE8a7MB8+
7wIDAQAB
-----END PUBLIC KEY-----
"""

  def checklicense(self):
    '''
        Performs a signature check on the internal license self.license

        returns: true/false
                if signature is valid
    '''
    signature = base64.b64decode(self.SIGNATURE)
    #
    # verfify signature

    ## obsolet : at max should be part of the server -
    ## the client does not need to do a license verification
    ## and we don't need M2Crypto :-)

    return 1

  def setlicense(self, license):
    '''
        This sets the license internally
    '''
    self.license = license
    self.lines = self.license.rsplit('\n')

    self.LICENSE = ""
    self.SIGNATURE = ""
    read_license = 0
    read_signature = 0
    for l in self.lines:
        l += "\n"
        if (l == "-----BEGIN LICENSE-----\n"):
            read_license = 1
        elif (l == "-----END LICENSE-----\n"):
            read_license = 0
        elif (l == "-----BEGIN LICENSE SIGNATURE-----\n"):
            read_signature = 1
        elif (l == "-----END LICENSE SIGNATURE-----"):  #
            read_signature = 0
        elif (l == "-----END LICENSE SIGNATURE-----\n"):  # sometimes we got an \n at the end
            read_signature = 0
        else:
            if read_license == 1:
                self.LICENSE += l
                (key, sep, value) = l.partition('=')
                self.licDict[key] = value.rstrip()
            elif read_signature == 1:
                self.SIGNATURE += l.rstrip()

    if self.logging:
        self.log.debug("[setlicense] type: %s" % type(license))
        self.log.debug("[setlicense] license: %s" % license)
        self.log.debug("[setlicense] LICENSE: %s" % self.LICENSE)
        self.log.debug("[setlicense] SIGNATURE: %s" % self.SIGNATURE)

  def getlicenseDict(self):
    '''
        returns the licenses as a dictionary
    '''
    return self.licDict

  def getlicense(self):
    return self.license

  def getTokenNum(self):
    if self.logging:
        self.log.debug("[getTokenNum] %s" % self.licDict.get('token-num',""))

    ret = self.licDict.get('token-num')
    try:
        ret = int(token_num)
    except:
        pass
    return ret

  def getlicensee(self):
    if self.logging: self.log.debug("[getlicensee] %s" % self.licDict.get('licensee',""))
    return self.licDict.get('licensee','')

