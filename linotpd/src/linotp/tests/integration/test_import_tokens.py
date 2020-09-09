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
Test token import via UI
"""

# pylint: disable=redefined-outer-name

import os

import pytest

from linotp_selenium_helper.token_import import TokenImportAladdin, TokenImportError

@pytest.fixture
def aladdin(manage_ui):
    return TokenImportAladdin(manage_ui)

def check_menu_is_closed(manage_ui):
    """
    Check that import menu is closed

    By checking that the aladdin menu entry is not visible
    """
    # Find element even when hidden
    menu_element = manage_ui.driver.find_element_by_id('menu_load_aladdin_xml_tokenfile')
    assert not menu_element.is_displayed(), menu_element

def test_token_import_aladdin_invalid_xml(manage_ui, aladdin):

    with pytest.raises(TokenImportError):
        aladdin.do_import(
            file_path=os.path.join(manage_ui.test_data_dir,
                                    'wrong_token.xml'))
    check_menu_is_closed(manage_ui)
