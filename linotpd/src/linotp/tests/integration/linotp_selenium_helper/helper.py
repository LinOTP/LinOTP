# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys

LOG = logging.getLogger(__name__)

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
        try:
            session = r.cookies['admin_session']
        except Exception as exception:
            LOG.error('Could not get session %r' % exception)
            raise exception
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
    try:
        for key in key_array:
            current_config = current_config[key]
        return current_config
    except KeyError:
        if not required:
            return default
        else:
            raise Exception("Testconfig entry %s is required" % '.'.join(key_array))

