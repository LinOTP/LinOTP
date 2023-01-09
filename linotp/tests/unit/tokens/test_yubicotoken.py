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
import pytest
from mock import patch

from linotp.tokens.yubicotoken import YubicoApikeyException, YubicoTokenClass


class DummyDBToken:
    """Dummy db token class - required to instantiate a linotp token."""

    def setType(self, typ):
        """min method the db token class has to have."""
        self.typ = typ


@patch("linotp.tokens.yubicotoken.getFromConfig")
def test_yubico_no_api_key(m_getFromConfig):
    """Verify that by default there is no apikey."""

    m_getFromConfig.return_value = None

    yubikey_token = YubicoTokenClass(DummyDBToken())
    with pytest.raises(YubicoApikeyException) as exx:
        yubikey_token.checkOtp("1213", counter=2, window=2)

    assert exx.typename == "YubicoApikeyException"
    assert str(exx.value) == "Yubico apiKey or apiId not configured!"
