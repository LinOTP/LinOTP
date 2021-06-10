# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
auth controller - to do authentication tests
"""


import logging


from linotp.flap import render_mako as render, response, tmpl_context as c

from linotp.controllers.base import BaseController, add_hyphenated_url
from linotp.lib.util import get_version
from linotp.lib.util import get_copyright_info
from linotp.lib.reply import sendError

from linotp.lib.config import getLinotpConfig
from linotp.lib.context import request_context

from linotp.model import db

log = logging.getLogger(__name__)

optional = True
required = False


class AuthController(BaseController):
    def __init__(self, name, install_name="", **kwargs):
        super(AuthController, self).__init__(
            name, install_name=install_name, **kwargs
        )

        # Add a specific handler for /auth/index
        self.add_url_rule("index", "index", view_func=self.index)

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:

            c.version = get_version()
            c.licenseinfo = get_copyright_info()

        except Exception as exx:
            log.error("[__before__::%r]", action)
            db.session.rollback()
            return sendError(response, exx, context="before")

    def index(self):
        """
        This is the method for testing authentication

        Call it directly in your browser like this
            http(s)://server/auth/index
        """
        log.debug("[index] index, authenticating user")
        return render("/auth.mako")

    def index3(self):
        """
        This is the method for testing authentication

        Call it directly in your browser like this
            http(s)://server/auth/index3
        """
        log.debug("[index3] index, authenticating user")
        return render("/auth3.mako")

    @add_hyphenated_url
    def challenge_response(self):
        """
        This is the method for testing challenge-response
        authentication

        Call it directly in your browser like this
            http(s)://server/auth/challenge_response
        """
        log.debug("[challenge_response] index, authenticating user")
        return render("/auth-challenge-response.mako")

    def qrtoken(self):
        """
        This is the method for testing authentication
        using your LinOTP QR Token

        Call it directly in your browser like this
            http(s)://server/auth/qrtoken
        """
        log.debug("[qrtoken] authenticating user")
        return render("/auth-qrtoken.mako")

    def pushtoken(self):
        """
        This is the method for testing authentication
        using your LinOTP Push Token

        Call it directly in your browser like this
            http(s)://server/auth/pushtoken
        """
        log.debug("[pushtoken] authenticating user")
        return render("/auth-push.mako")

    def ocra2(self):
        """
        This is the method for testing ocra2 tokens

        Call it directly in your browser like this
            http(s)://server/auth/ocra2
        """
        log.debug("[ocra2] authenticating user")
        return render("/auth-ocra2.mako")


# eof##########################################################################
