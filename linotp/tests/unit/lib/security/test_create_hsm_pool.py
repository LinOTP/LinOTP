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
"""
Tests to check the exception handling for createHSMPool
These tests are far from complete and can not be the only point of
reliance for changes in the code base
"""

from unittest.mock import patch

import flask
import pytest

from linotp.lib.security.provider import SecurityProvider


@patch("linotp.lib.security.provider.SecurityProvider.loadSecurityModule")
@patch("linotp.lib.security.provider.SecurityProvider._getHsmPool_")
@patch("linotp.lib.security.provider.SecurityProvider.__init__")
def test_create_hsm_pool(mock_init, mock_get_hsm_pool, mock_load_security_module):
    poolsize = 20
    mock_init.return_value = None
    mock_get_hsm_pool.return_value = None

    mock_load_security_module.side_effect = Exception("Mocked Exception to be caught")

    # hook for local provider test
    security_provider = SecurityProvider()
    security_provider.config = {
        "default": {
            "crypted": "FALSE",
            "module": "linotp.lib.security.default.DefaultSecurityModule",
            "poolsize": poolsize,
        }
    }

    security_provider.hsmpool = {"default": ""}
    created_pool = security_provider.createHSMPool("default", None, None)

    assert len(created_pool) == poolsize
    # test the content of one of the connections
    assert created_pool[0]["obj"] is None
    assert (
        created_pool[0]["error"]
        == "'default': " + mock_load_security_module.side_effect.__repr__()
    )

    # check that all elements are the same:
    first_elem = created_pool[0]
    assert all(elem == first_elem for elem in created_pool)


def test_hsm_functionality(app):
    """
    Test functionality of the hsm by:

    """

    # hook for local provider test
    security_provider = SecurityProvider()
    security_provider.load_config(app.config)
    security_provider.createHSMPool("default")
    security_provider.setupModule("default", {"passwd": "test123"})

    # runtime catch an hsm for session
    hsm = security_provider.getSecurityModule()

    passw1_orig = b"password"
    encpass = hsm["obj"].encryptPassword(passw1_orig)
    passw1_decrypted = hsm["obj"].decryptPassword(encpass)

    assert passw1_decrypted == passw1_orig

    hsm2 = security_provider.getSecurityModule(sessionId="session2")

    passw2_orig = b"password"
    encpass = hsm2["obj"].encryptPassword(passw2_orig)
    passw2_decrypted = hsm2["obj"].decryptPassword(encpass)

    assert passw2_decrypted == passw2_orig

    # session shutdown
    assert security_provider.dropSecurityModule(sessionId="session2")
    assert security_provider.dropSecurityModule()


@pytest.mark.parametrize(
    "request_path,should_have_hsm",
    [
        ("/static/whatever", False),
        ("/notstatic/whatever", True),
        ("/whatever/whatever", True),
    ],
)
def test_hsm_for_static_requests(app, request_path, should_have_hsm):
    """For static requests there should be no hsm allocated
    static request paths start with '/static/'
    This is the exact value of app.static_url_path
    """

    flask.request.environ["REMOTE_ADDR"] = "11.12.13.14"  # Any will do
    with (
        patch("linotp.app.request.path", request_path) as _,
        patch("linotp.app.init_key_partition") as _,
        patch("linotp.app.c") as context_mock,
    ):
        context_mock.hsm = {}
        app.create_context()

    if should_have_hsm:
        assert "obj" in context_mock.hsm
    else:
        assert "obj" not in context_mock.hsm
