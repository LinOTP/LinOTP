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
"""

import json
import logging

log = logging.getLogger(__name__)


class TokenInfoMixin(object):

    def getTokenInfo(self):
        info = {}

        tokeninfo = self.token.getInfo()
        if tokeninfo is not None and len(tokeninfo.strip()) > 0:
            try:
                info = json.loads(tokeninfo)
            except Exception as e:
                log.exception('JSON loading error in token info: %r' % (e))

        return info

    def setTokenInfo(self, info):

        if info is not None:
            tokeninfo = u'' + json.dumps(info, indent=0)
            self.token.setInfo(tokeninfo)

    def addToTokenInfo(self, key, value):
        info = {}
        tokeninfo = self.token.getInfo()

        if tokeninfo:
            info = json.loads(tokeninfo)

        info[key] = value

        self.setTokenInfo(info)

    def getFromTokenInfo(self, key, default=None):
        ret = default

        info = self.getTokenInfo()

        if key in info:
            ret = info.get(key, default)
        return ret

    def removeFromTokenInfo(self, key):
        info = self.getTokenInfo()
        if key in info:
            del info[key]
            self.setTokenInfo(info)

# eof #
