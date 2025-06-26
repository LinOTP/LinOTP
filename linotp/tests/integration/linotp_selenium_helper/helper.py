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
"""Contains helper functions"""

import logging
from typing import Any

from pytest_testconfig import config, load_ini
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.select import Select
from selenium.webdriver.support.ui import WebDriverWait

from linotp.settings import _config_schema

LOG = logging.getLogger(__name__)


def _find_and_wait(driver, by, value):
    """
    Returns the element defined by 'by' and 'value', waiting up to 10 seconds
    for it to appear.
    """
    return WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((by, value))
    )


def _find_and_wait_for_all(driver, by, value):
    """
    Returns the element defined by 'by' and 'value', waiting up to 10 seconds
    for it to appear.
    """
    return WebDriverWait(driver, 10).until(
        EC.visibility_of_all_elements_located((by, value))
    )


def find_by_css(driver, selector):
    """
    Returns the element defined by the CSS selector, waiting up to 10 seconds
    for it to appear.
    """
    return _find_and_wait(driver, By.CSS_SELECTOR, selector)


def find_all_by_css(driver, selector):
    """
    Returns all elements matched by the CSS selector, waiting up to 10 seconds
    for all of them to appear.
    """
    return _find_and_wait_for_all(driver, By.CSS_SELECTOR, selector)


def find_by_id(driver, id_value):
    """
    Returns the element defined by the HTML id, waiting up to 10 seconds for it
    to appear.
    """
    return _find_and_wait(driver, By.ID, id_value)


def find_by_class(driver, class_name):
    """
    Returns the element defined by the HTML class, waiting up to 10 seconds for it
    to appear.
    """
    return _find_and_wait(driver, By.CLASS_NAME, class_name)


def find_by_xpath(driver, xpath):
    """
    Returns the element defined by the xpath, waiting up to 10 seconds for it
    to appear.
    """
    return _find_and_wait(driver, By.XPATH, xpath)


def fill_form_element(driver, element_id, data):
    """Clear element and fill with values"""
    e = find_by_id(driver, element_id)
    e.clear()
    e.send_keys(data)


def fill_element_from_dict(driver, element_id, name, data_dict):
    """
    Verify that we have the named element in dict. Then clear the element
    and fill with the value in the data dict
    """
    assert name in data_dict, "Data dict needs element %s" % name
    return fill_form_element(driver, element_id, data_dict[name])


def hover(driver, element):
    """Allows the mouse to hover over 'element'"""
    hov = ActionChains(driver).move_to_element(element)
    hov.perform()


def select(driver, select_element, option_text):
    """Select an option from a HTML <select> (dropdown)"""

    selections = Select(select_element)
    if selections.first_selected_option.text.strip() != option_text:
        selections.select_by_visible_text(option_text)


def get_default_app_setting(config_name: str) -> Any:
    """
    Helper to give integration tests access to the default app config
    """
    return _config_schema.find_item(config_name).default


def load_tconfig_from_file(filename):
    """
    Load configuration from filename given. This is an alternative way
    to load the configuration when not running tests via nose runner.
    Another alternative is via the environment variable:

      NOSE_TESTCONFIG_AUTOLOAD_INI=<filename>
    """
    load_ini(filename, encoding="utf-8")


def get_from_tconfig(key_array, default=None, required=False):
    """Gets a value from the testconfig file.

    :param key_array: The key we are looking for. For example config['linotp']['host']
                      would be specified as ['linotp', 'host']
    :param default: The default value to return if nothing is found in the config file
    :param required: Is this entry required? An exception will be raised if no value is
                     found and it was required.
    :return: A string or 'default', which could be of any type
    """
    assert key_array is not None and len(key_array) > 0
    current_config = config

    if required and not len(current_config):
        raise Exception("Testconfig is empty. See Readme for details (--tc-file)")

    try:
        for key in key_array:
            current_config = current_config[key]
        return current_config
    except KeyError:
        if not required:
            return default
        else:
            raise Exception("Testconfig entry %s is required" % ".".join(key_array))


# Helper for skipping tests if there is no radius server


def is_radius_disabled():
    disable_radius = get_from_tconfig(["radius", "disable"], default="False")
    return disable_radius.lower() == "true"


def close_alert_and_get_its_text(driver, accept=True):
    """
    Close alert box and get the text contents

    @param driver: Selenium driver
    @param accept: Accept alert? Defaults to accept, cancel=False

    @return: Alert box text
    """
    alert = driver.switch_to.alert
    alert_text = alert.text
    if accept:
        alert.accept()
    else:
        alert.dismiss()
    return alert_text


class BackendException(Exception):
    """
    Representation of a backend error
    """

    def __init__(self, response, url=None):
        super().__init__()
        code: int = response.status_code
        if code != 200:
            self.code: int = response.status_code
            self.description: str = response.reason
        else:
            error = response.json()["result"]["error"]
            self.code: int = error["code"]
            self.description: str = error["message"]
        if url:
            self.url: str = url
        else:
            self.url: str = response.url

    def __str__(self) -> str:
        return f"{super().__str__()} {self.url} {self.code} - {self.description}"
