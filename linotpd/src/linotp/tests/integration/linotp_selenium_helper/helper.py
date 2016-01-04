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
"""Contains helper functions"""

import requests
from requests.auth import HTTPDigestAuth
import logging
from testconfig import config
from urlparse import urlparse

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

LOG = logging.getLogger(__name__)


def _find_and_wait(driver, by, value):
    """
    Returns the element defined by 'by' and 'value', waiting up to 10 seconds
    for it to appear.
    """
    return WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((by, value))
        )

def find_by_css(driver, selector):
    """
    Returns the element defined by the CSS selector, waiting up to 10 seconds
    for it to appear.
    """
    return _find_and_wait(driver, By.CSS_SELECTOR, selector)

def find_by_id(driver, id_value):
    """
    Returns the element defined by the HTML id, waiting up to 10 seconds for it
    to appear.
    """
    return _find_and_wait(driver, By.ID, id_value)

def fill_form_element(driver, element_id, data):
    """ Clear element and fill with values """
    e = find_by_id(driver, element_id)
    e.clear()
    e.send_keys(data)

def fill_element_from_dict(driver, element_id, name, data_dict):
    """
    Verify that we have the named element in dict. Then clear the element
    and fill with the value in the data dict
    """
    assert name in data_dict, 'Data dict needs element %s' % name
    return fill_form_element(driver, element_id, data_dict[name])


def hover(driver, element):
    """Allows the mouse to hover over 'element'"""
    hov = ActionChains(driver).move_to_element(element)
    hov.perform()

def select(driver, select_element, option_text):
    """Select an option from a HTML <select> (dropdown)"""
    for option in select_element.find_elements_by_tag_name('option'):
        if option.text == option_text:
            option.click()

def get_session(base_url, user=None, pwd=None):
    '''
    return a LinOTP Session

    :param base_url: the linotp base url
    :param user: the user
    :param pwd: the password of the user

    :return: session (string)
    '''
    session = None
    if user != None:
        url = base_url + 'admin/getsession'
        r = requests.get(url, auth=HTTPDigestAuth(user, pwd), verify=False)

        LOG.debug("Content:\n%s" % r.text)
        if r.status_code != 200:
            raise Exception('Admin login failed')
        session = None
        domain = urlparse(base_url).netloc.split(':')[0]
        exceptions = []
        for d in (domain, domain + ".local", None):
            # We try to find any cookie containing 'admin_session'. Sometimes
            # the Cookie domain is not completely clear therefore we try
            # several alternatives and as last resource try to get any cookie
            # matching 'admin_session' no matter what the domain (=None).
            try:
                session = r.cookies.get('admin_session', domain=d)
                if session:
                    break
            except requests.cookies.CookieConflictError as exc:
                exceptions.append(exc)
        if not session:
            raise Exception('Could not get session %r' % exceptions)
    return session

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

    if not len(current_config):
        raise Exception("Testconfig is empty. See Readme for details (--tc-file)")

    try:
        for key in key_array:
            current_config = current_config[key]
        return current_config
    except KeyError:
        if not required:
            return default
        else:
            raise Exception("Testconfig entry %s is required" % '.'.join(key_array))

# Helper for skipping tests if there is no radius server
def is_radius_disabled():
    disable_radius = get_from_tconfig(['radius', 'disable'], default='False')
    return disable_radius.lower() == 'true'

