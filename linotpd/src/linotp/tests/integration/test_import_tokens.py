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

from linotp_selenium_helper.manage_ui import ManageUi
from linotp_selenium_helper.token_import import TokenImportAladdin, TokenImportError
from linotp_selenium_helper.token_view import TokenView

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

def test_token_import_aladdin_xml(manage_ui: ManageUi, aladdin: TokenImportAladdin):
    """
    Test import of valid aladdin tokens
    """
    aladdin_xml_path = os.path.join(manage_ui.test_data_dir, 'aladdin.xml')
    aladdin.do_import(file_path=aladdin_xml_path)

    tokenview = manage_ui.token_view

    token_serials = ('00040008CFA5', '00040008CFA52', 'oath137332', 'oath12482B')

    # Check the grid lines for the imported tokens
    grid = tokenview.get_grid_contents()
    for serial in token_serials:
        # Find token in grid
        token_row = [row for row in grid if row['Serial Number'] == serial]
        token_row_contents = token_row[0]
        assert token_row_contents['Serial Number'] == serial
        assert token_row_contents['Type'] == 'HMAC'
        assert token_row_contents['Description'] == 'imported'

    # Check token info contents for one of the tokens
    serial_to_check = token_serials[0]
    token_info = tokenview.get_token_info(serial_to_check)
    assert token_info['LinOtp.TokenType'] == 'HMAC'
    assert token_info['LinOtp.TokenSerialnumber'] == serial_to_check

    check_menu_is_closed(manage_ui)

def test_token_import_aladdin_invalid_xml(manage_ui: ManageUi, aladdin: TokenImportAladdin):

    with pytest.raises(TokenImportError):
        aladdin.do_import(
            file_path=os.path.join(manage_ui.test_data_dir,
                                    'wrong_token.xml'))
    check_menu_is_closed(manage_ui)
