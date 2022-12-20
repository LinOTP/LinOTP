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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

"""
Test token import via UI
"""

# pylint: disable=redefined-outer-name

import itertools
import os
from time import sleep

import pytest
from selenium.webdriver.common.by import By

from linotp_selenium_helper.manage_ui import AlertBoxHandler, ManageUi
from linotp_selenium_helper.token_import import (
    TokenImportAladdin,
    TokenImportError,
    TokenImportOATH,
)

# All the tests in this file make use of the musicians realm as default
pytestmark = pytest.mark.usefixtures("musicians_realm")


@pytest.fixture
def aladdin(testcase):
    return TokenImportAladdin(testcase.manage_ui)


@pytest.fixture
def oathcsv_importer(testcase):
    return TokenImportOATH(testcase.manage_ui)


def check_menu_is_closed(current_manage_ui):
    """Check that import menu is closed.

    By checking that the aladdin menu entry is not visible
    """
    # Move the mouse somewhere else to ensure the menu is closed
    current_manage_ui.find_by_id("logo").click()

    current_manage_ui.wait_for_element_disappearing(
        "#menu_load_aladdin_xml_tokenfile"
    )


def test_token_import_aladdin_xml(testcase, aladdin: TokenImportAladdin):
    """Test import of valid aladdin tokens."""
    aladdin_xml_path = os.path.join(
        testcase.manage_ui.test_data_dir, "aladdin.xml"
    )
    aladdin.do_import(file_path=aladdin_xml_path)

    token_serials = (
        "00040008CFA5",
        "00040008CFA52",
        "oath137332",
        "oath12482B",
    )

    # Check the grid lines for the imported tokens
    assert_tokens_are_in_grid(testcase.manage_ui, token_serials, "HMAC")

    # Check token info contents for one of the tokens
    serial_to_check = token_serials[0]
    token_info = testcase.manage_ui.token_view.get_token_info(serial_to_check)
    assert token_info["LinOtp.TokenType"] == "HMAC"
    assert token_info["LinOtp.TokenSerialnumber"] == serial_to_check

    check_menu_is_closed(testcase.manage_ui)


def test_token_import_aladdin_invalid_xml(
    testcase, aladdin: TokenImportAladdin
):
    """Test import of invalid xml."""

    with pytest.raises(TokenImportError):
        aladdin.do_import(
            file_path=os.path.join(
                testcase.manage_ui.test_data_dir, "wrong_token.xml"
            )
        )
    check_menu_is_closed(testcase.manage_ui)


def test_token_import_oath_csv(testcase, oathcsv_importer: TokenImportOATH):
    """Test import of valid oath csv tokens."""

    #   data to be tested against:
    oath_csv_path = os.path.join(
        testcase.manage_ui.test_data_dir, "oath_tokens.csv"
    )
    token_serials = (
        "tok1",
        "tok2",
        "tok3",
        "tok4",
    )
    token_types = ["HMAC", "TOTP", "HMAC", "TOTP"]

    oathcsv_importer.do_import(file_path=oath_csv_path)

    # check the alert box
    alert_box = AlertBoxHandler(testcase.manage_ui)
    assert (
        alert_box.last_line.text
        == "Token import result: 4 tokens were imported from the oath_tokens.csv file. OK"
    )

    # check the grid lines for the imported tokens
    assert_tokens_are_in_grid(testcase.manage_ui, token_serials, token_types)


def test_token_import_oath_csv_invalid_seed(
    testcase, oathcsv_importer: TokenImportOATH
):
    "Test import of invalid oath csv tokens"

    # save the initial tokens for later comparison
    tokens_at_first = testcase.manage_ui.token_view._get_token_list()

    #   data to be tested against:
    oath_csv_path = os.path.join(
        testcase.manage_ui.test_data_dir, "oath_tokens_bad_seed.csv"
    )
    token_serials = (
        "tok1",
        "tok2",
        "tok3",
        "tok4",
    )
    token_types = ["HMAC", "TOTP", "HMAC", "TOTP"]
    with pytest.raises(TokenImportError) as exc_info:
        oathcsv_importer.do_import(file_path=oath_csv_path)

    assert (
        str(exc_info.value)
        == "Import failure:error:Failed to import token: InvalidSeedException('The provided token seed contains non-hexadecimal characters') OK"
    )

    # check the alert box showing the correct information
    alert_box = AlertBoxHandler(testcase.manage_ui)
    assert (
        alert_box.last_line.text
        == "Failed to import token: InvalidSeedException('The provided token seed contains non-hexadecimal characters') OK"
    )

    # check that no token was imported
    tokens_after_import_attempt = (
        testcase.manage_ui.token_view._get_token_list()
    )
    tokens_at_first == tokens_after_import_attempt


def assert_tokens_are_in_grid(
    manage_ui,
    token_serials,
    token_types=[
        "HMAC",
    ],
):
    """
    Checks all the tokens in the list and their corresponding
    types to be present in the grid of the Token View

    :param manage_ui: the current manage_ui object
    :param token_serials: list of tokens which should be checked
    :param token_types: list of corresponding token types or only one token type for all cases
    """

    if len(token_types) == 1 or isinstance(token_types, str):
        token_iterator = zip(token_serials, itertools.repeat(token_types))
    else:
        token_iterator = zip(token_serials, token_types)

    tokenview = manage_ui.token_view
    grid = tokenview.get_grid_contents()

    for serial, token_type in token_iterator:
        # Find token in grid
        token_row = [row for row in grid if row["Serial Number"] == serial]
        assert len(token_row) == 1, "token not in list or repeated"
        token_row_contents = token_row[0]
        assert token_row_contents["Serial Number"] == serial
        assert token_row_contents["Type"] == token_type
        assert token_row_contents["Description"] == "imported"
