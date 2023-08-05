# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
"""Tests for text_util re_encode which is required for linotp2 migration """

import logging

import pytest

from linotp.model.migrate import re_encode

log = logging.getLogger(__name__)


def test_iso8859():
    """Test for iso-8859-1 input re_encoding."""

    utf8_str = "äöüß€"
    iso8859_15_str = bytes(utf8_str, encoding="utf-8").decode("iso-8859-15")

    with pytest.raises(UnicodeDecodeError):
        re_encode(utf8_str)

    re_utf8_str = re_encode(iso8859_15_str)
    assert utf8_str == re_utf8_str

    assert re_encode(None) is None

    assert re_encode("") == ""
