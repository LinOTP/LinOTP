# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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


import unittest

import pytest
from mock import patch

from linotp.lib.support import verify_token_volume

LICENSE = {
    "version": "2",
    "issuer": "LSE Leading Security Experts GmbH",
    "comment": "License for LSE LinOTP 2",
    "licensee": "Testkunde",
    "address": "unknown/unbekannt",
    "contact-name": "unknown/unbekannt",
    "contact-phone": "unknown/unbekannt",
    "contact-email": "hs@unknown/unbekannt",
    "token-num": "3",
    "date": "2021-09-08",
    "subscription": "2025-09-03",
    "expire": "2025-09-03",
}


fake_context = {}


@pytest.mark.usefixtures("app")
class LicenseSupportTestCase(unittest.TestCase):
    @patch("linotp.lib.support.context", new=fake_context)
    @patch("linotp.lib.support.getTokenNumResolver")
    def test_token_volume(self, mocked_getTokenNumResolver):
        """test verify_token_volume including grace response."""

        mocked_getTokenNumResolver.return_value = 2
        valid, detail = verify_token_volume(lic_dict=LICENSE)

        assert valid
        assert detail == ""

        mocked_getTokenNumResolver.return_value = 3
        valid, detail = verify_token_volume(lic_dict=LICENSE)

        assert valid
        assert "Grace limit reached" in detail

        mocked_getTokenNumResolver.return_value = 6
        valid, detail = verify_token_volume(lic_dict=LICENSE)

        assert not valid
        assert "Grace limit reached" not in detail

        return
