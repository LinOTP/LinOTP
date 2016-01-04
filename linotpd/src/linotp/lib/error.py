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
''' definition of some specific error classes'''

import logging
log = logging.getLogger(__name__)


class LinotpError(Exception):

    def __init__(self, description=u"LinotpError!", id=10):
        self.id = id
        self.message = description
        Exception.__init__(self, description)

    def getId(self):
        return self.id

    def getDescription(self):
        return self.message

    def __unicode__(self):
        pstr = u"ERR%d: %r"
        if type(self.message) in [str, unicode]:
            pstr = u"ERR%d: %s"
        return pstr % (self.id, self.message)

    def __str__(self):
        pstr = u"ERR%d: %r"
        if type(self.message) in [str, unicode]:
            pstr = "ERR%d: %s"

        ### if we have here unicode, we might fail with conversion error
        try:
            res = pstr % (self.id, self.message)
        except Exception as exx:
            res = u"ERR%d: %r" % (self.id, self.message)
        return res


    def __repr__(self):
        ret = '%s(description=%r, id=%d)' % (type(self).__name__, self.message, self.id)
        return ret


class ValidateError(LinotpError):
    def __init__(self, description="validation error!", id=10):
        LinotpError.__init__(self, description=description, id=id)


class TokenAdminError(LinotpError):
    def __init__(self, description="token admin error!", id=10):
        LinotpError.__init__(self, description=description, id=id)


class ConfigAdminError(LinotpError):
    def __init__(self, description="config admin error!", id=10):
        LinotpError.__init__(self, description=description, id=id)


class UserError(LinotpError):
    def __init__(self, description="user error!", id=905):
        LinotpError.__init__(self, description=description, id=id)


class ServerError(LinotpError):
    def __init__(self, description="server error!", id=905):
        LinotpError.__init__(self, description=description, id=id)


class HSMException(LinotpError):
    def __init__(self, description="hsm error!", id=707):
        LinotpError.__init__(self, description=description, id=id)


class SelfserviceException(LinotpError):
    def __init__(self, description="selfservice error!", id=807):
        LinotpError.__init__(self, description=description, id=id)


class ParameterError(LinotpError):
    def __init__(self, description="unspecified parameter error!", id=905):
        LinotpError.__init__(self, description=description, id=id)


class TokenTypeNotSupportedError(LinotpError):
    def __init__(self, description="this token type is not supported on this setup!", id=906):
        LinotpError.__init__(self, description=description, id=id)


#eof###########################################################################

