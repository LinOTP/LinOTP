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
"""Contains TokenView class"""

import time

class TokenViewException(Exception):
    pass


class TokenView:
    """Represents the 'Token View' tab in the LinOTP WebUI"""

    def __init__(self, driver, base_url):
        """"""
        self.driver = driver
        self.base_url = base_url

    def _open_tab_token_view(self):
        """Select the 'Token View' tab"""
        token_view = self.driver.find_element_by_xpath("//div[@id='tabs']"
                                                      "/ul/li[1]/a/span")
        time.sleep(1)
        token_view.click()

    def select_token(self, token_serial):
        """Selects (clicks on) a token in the WebUI. This function does not reload
           the page (because otherwise the selection would be lost) neither before
           nor after the selection.
        """
        self._open_tab_token_view()
        token_serials = self.driver.find_elements_by_css_selector("#token_table tr "
                                                              "td:first-child div")
        for token in token_serials:
            if token.text == token_serial:
                token.click()

    def get_token_info(self, token_serial):
        """
        Extracts the token info from the WebUI and returns it as a dictionary.
        """
        keys_with_subtable = ['LinOtp.TokenInfo', 'LinOtp.RealmNames']
        self.select_token(token_serial)
        self.driver.find_element_by_id("button_tokeninfo").click()
        token_info = {}
        rows = self.driver.find_elements_by_css_selector("#dialog_token_info > table >tbody > tr")
        for row in rows:
            tds = row.find_elements_by_css_selector("td.tokeninfoOuterTable")
            key = tds[0].text
            value_element = tds[1]
            if key in keys_with_subtable:
                inner_rows = value_element.find_elements_by_css_selector('table.tokeninfoInnerTable tr')
                if key == 'LinOtp.RealmNames':
                    token_info[key] = []
                else:
                    token_info[key] = {}
                for inner_row in inner_rows:
                    inner_tds = inner_row.find_elements_by_css_selector("td.tokeninfoInnerTable")
                    if key == 'LinOtp.RealmNames':
                        inner_value = inner_tds[0].text
                        token_info[key].append(inner_value)
                    else:
                        inner_key = inner_tds[0].text
                        inner_value = inner_tds[1].text
                        token_info[key][inner_key] = inner_value
            else:
                token_info[key] = value_element.text
        return token_info
