# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2015 - 2019 KeyIdentity GmbH
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

import logging
from . import helper
import os
import requests
import re

from operator import methodcaller
from warnings import warn

from selenium.common.exceptions import WebDriverException, NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from .manage_elements import ManageDialog
from .realm import RealmManager
from .policy import PolicyManager
from .system_config import SystemConfig
from .user_id_resolver import UserIdResolverManager
from .user_view import UserView
from .token_view import TokenView

"""
This file contains the main manage page class
"""


class ManageUi(object):
    """
    Object for representing the manage page itself. There should be
    a single ManageUi object to represent the browser page
    """

    URL = "/manage"

    testcase = None
    "The UnitTest class that is running the tests"

    welcome_screen = None
    "Welcome screen dialog"

    useridresolver_manager = None
    "UserIdResolver manager dialog"

    realm_manager = None
    "Realm manager dialog"
    token_view = None
    "Tokens tab"

    user_view = None
    "Users tab"

    policy_view = None
    "Policy tab"

    alert_dialog = None
    "Access to the alert box dialog element"

    # CSS selectors

    # Menu entry "Import Token File"
    MENU_LINOTP_IMPORT_TOKEN_CSS = '#menu > li:nth-of-type(3)'
    "CSS of the LinOTP Import Token menu"

    # Menu entry "LinOTP Config"
    MENU_LINOTP_CONFIG_CSS = '#menu > li'
    "CSS of the LinOTP Config menu"

    def __init__(self, testcase):
        """
        Create a new ManageUi instance. Normally this will be called
        from a derived class

        :param testcase: The test case that is controlling the UI
        """
        self.testcase = testcase
        self.test_data_dir = os.path.normpath(os.path.join(
            os.path.split(__file__)[0], '..', 'testdata'
        ))

        self.welcome_screen = ManageDialog(
            self, 'welcome_screen', 'welcome_screen_close')

        self.useridresolver_manager = UserIdResolverManager(self)
        self.realm_manager = RealmManager(self)
        self.token_view = TokenView(self)
        self.user_view = UserView(self)
        self.policy_view = PolicyManager(self)
        self.system_config = SystemConfig(self)

        self.alert_dialog = ManageDialog(self, 'alert_box')

    def is_url_open(self):
        possible_urls = (self.URL, self.URL + '/', self.URL + '/#')
        return self.driver.current_url.endswith(possible_urls)

    @property
    def manage_url(self):
        """
        The URL of the page
        """
        return self.testcase.base_url + self.URL

    @property
    def alert_box_handler(self):
        """
        Return an instance of an alert box handler.
        """
        return AlertBoxHandler(self)

    @property
    def driver(self):
        """
        Return a reference to the selenium driver
        """
        return self.testcase.driver

    def check_url(self):
        """
        Check we are on the right page
        """
        assert self.is_url_open(), \
            'URL %s should end with %s - page not loaded?' % \
            (self.driver.current_url, self.URL)
        assert self.driver.title == 'Management - LinOTP'

    def find_by_css(self, css_value):
        """
        Return the element indicated by CSS selector
        """
        self.check_url()
        return helper.find_by_css(self.driver, css_value)

    def find_all_by_css(self, css_value):
        """
        Return a list of elements indicated by CSS selector
        """
        self.check_url()
        return self.driver.find_elements_by_css_selector(css_value)

    def find_by_id(self, id_value):
        """
        Return the element by ID
        """
        self.check_url()
        return helper.find_by_id(self.driver, id_value)

    def find_by_class(self, class_name):
        """
        Return the element by its class name
        """
        return helper.find_by_class(self.driver, class_name)

    def find_by_xpath(self, xpath):
        """
        Return the element by its xpath
        """
        return helper.find_by_xpath(self.driver, xpath)

    def open_manage(self):
        if not self.is_url_open():
            self.driver.get(self.manage_url)

            self.welcome_screen.close_if_open()

    def activate_menu_item(self, menu_css, menu_item_id):
        """
        Open the manage UI and select the given menu item.

        If there are open dialogs in the UI, these will be
        closed first.

        Throws an assertion if this dialog does not have an associated menu entry
        """
        assert menu_item_id, "Open dialog requested but no menu id specified (menu_item_id"
        assert menu_css, "Open dialog requested but no toplevel menu specified (menu_css)"

        self.open_manage()

        menu_element = self.find_by_css(menu_css)
        # helper.hover(self.driver, menu_element)

        self.close_dialogs_and_click(menu_element)

        self.find_by_id(menu_item_id).click()

    def close_dialogs_and_click(self, element):
        """
        Click the given element. If it fails, close
        all dialogs and then retry
        """
        try:
            element.click()
        except WebDriverException:
            self.close_all_dialogs()
            # Retry
            element.click()

    def close_all_dialogs(self):
        """
        Close all active dialogs down
        """

        # Find all open dialogs
        dialogs = self.find_all_by_css('.ui-dialog[style*="display: block"]')

        # Sort by depth (the z-index attribute in reverse order)
        dialogs.sort(
            key=methodcaller('get_attribute', 'z-index'), reverse=True)

        # Close them
        for dialog in dialogs:
            logging.debug('Closing dialog %s' %
                          dialog.get_attribute('aria-describedby'))
            dialog.find_element_by_css_selector(
                ManageDialog.CLOSEBUTTON_CSS).click()

    def check_alert(self, expected_text=None, click_accept=False, click_dismiss=False):
        """
        Process popup window:
        * check the text contents
        * close or dismiss the box

        :param expected_text: Text contents expected. An exception will be raised if not found
        :param click_accept: If set, will click the accept button
        :param click_dismiss: If set, will close the dialog
        """

        assert not click_accept or not click_dismiss, "check_alert cannot click both accept and dismiss"

        alert = self.driver.switch_to.alert
        alert_text = alert.text

        if click_accept:
            alert.accept()
        elif click_dismiss:
            alert.dismiss()

        if expected_text:
            assert alert_text == expected_text, "Expecting alert text:%s found:%s" % (
                expected_text, alert_text)

    def wait_for_waiting_finished(self):
        """
        Some elements, e.g. the realms dialog, take some time for network communication.
        During this period, the do_waiting is displayed. Wait for this to disappear
        """
        WebDriverWait(self.driver, 10).until_not(
            EC.visibility_of_element_located((By.ID, "do_waiting")))

    def is_element_visible(self, css):
        """
        Check whether a given element is visible without waiting
        """
        if not self.is_url_open():
            return False

        try:
            self.testcase.disableImplicitWait()
            element = EC.visibility_of_element_located(
                (By.CSS_SELECTOR, css))(self.driver)
            self.testcase.enableImplicitWait()
        except NoSuchElementException:
            return False
        is_visible = (element is not False)
        return is_visible

    def admin_api_call(self,
                       call,
                       params=None):
        """
        Give the API endpoint (call) and the params. Omit the session
        because it will be added automatically to your params.
        :param call Something like 'system/delPolicy'
        :param params Something like {'name': 'policy1'}
        :return Return json structure with API result
        """

        if(params is None):
            params = {}

        url = self.testcase.http_protocol + \
            "://" + self.testcase.http_host + \
            ":" + self.testcase.http_port + "/"

        params['session'] = helper.get_session(url,
                                               self.testcase.http_username,
                                               self.testcase.http_password)

        auth = requests.auth.HTTPDigestAuth(
            self.testcase.http_username,
            self.testcase.http_password)

        response = requests.post(url + call.strip('/'),
                                 auth=auth,
                                 params=params,
                                 cookies={'admin_session': params['session']},
                                 verify=False)

        response.raise_for_status()

        return response.json()


class MsgType(object):
    """
    Kind of an enum - Used in AlertBoxHandler to specify
    message types when needed for method paramaters
    """
    Error = 'error'
    Info = 'info'


class AlertBoxInfoLine(object):
    """
    Represenation of a line in the alert box
    """
    element = None # The WebElement representing this line
    ok_button = None
    classes = None
    type = None

    def __init__(self, element):
        self.parse(element)

    def parse(self, element):
        """
        Parse the line contents
        """
        self.element = element
        self.ok_button = element.find_element_by_css_selector('button')
        self.classes = element.get_attribute('class')

        # Determine type of message
        if 'error_box' in self.classes:
            self.type = 'error'
        elif 'info_box' in self.classes:
            self.type = 'info'
        else:
            warn('unknown info box message type. class={}'.format(self.classes))
            self.type = 'unknown'

    @property
    def text(self):
        return self.element.text

    def click_ok(self):
        """
        Click OK button on individual info line
        """
        self.ok_button.click()

    def __str__(self):
        return "{}:{}".format(self.type, self.text)

class AlertBoxHandler(object):
    """
    The AlertBoxHandler class allows to check the info/error
    messages on the /manage page thrown by admin actions
       e.g. after creating realms, tokens, etc.
    """

    manageui = None

    msgs_parent_id = 'info_box'
    link_close_all_msgs_class = 'close_all'

    def __init__(self, manage_ui):
        """
        Init the AlertBoxHandler
        :param manage_ui Reference to the manage_ui
        """
        self.manageui = manage_ui
        self.driver = manage_ui.driver

    def parse(self):
        """
        Parse the contents of the info box
        """

        # Get all elements in the box
        info_box_elements = self.driver.find_elements_by_xpath('//div[@id="info_box"]/*')

        self.info_bar = None
        self.info_lines = []
        self.close_all = None

        for e in info_box_elements:
            id = e.get_attribute('id')
            if id == 'info_bar':
                self.info_bar = e
            else:
                classes = e.get_attribute('class')
                if 'info_box' in classes or 'error_box' in classes:
                    self.info_lines.append(AlertBoxInfoLine(e))
                elif 'close_all' in classes:
                    self.close_all = e
                else:
                    warn('Could not parse info element box id={} class={}'.format(id, classes))

    def clear_messages(self):
        """
        Delete all action response messages
        """
        self.parse()

        if self.close_all:
            # 2 or more lines
            self.close_all.click()
        else:
            # 0 or 1 lines
            for l in self.info_lines:
                l.click_ok()

    def check_info_message(self, msg):
        """
        Wrap check_message with message type Info.
        """
        return self.check_message(msg, MsgType.Info)

    def check_error_message(self, msg):
        """
        Wrap check_message with message type Error.
        """
        return self.check_message(msg, MsgType.Error)

    @property
    def last_line(self):
        """
        Return the last (latest) line in the box, or None if empty

        Example of the 'mother' box covering the alert boxes.

         div id=info_box // mother info box
          +
          +-> div id=info_bar // auto created
          |
          +-> div class=info_box style="display:none" // auto created
          |
          +-> div class=info_box style="display:block" // 1st alert
          +   +>span
          |     +  "Realm created: "
          |     |
          |     +->span class=test_param1
          |               "test_realm2
          |
          +-> div class=error_box style="display:none"
          +
          |      // example for deleted alert box
          |      // display set to none
          |
          +-> div class=info_box style="display:block"

                 // new alert boxes are added at the
                 // end of the mother info box
                 //
                 // THE LAST BOX WE ARE TALKING ABOUT HERE!

        """
        self.parse()
        if self.info_lines:
            return self.info_lines[-1]
        else:
            return None


    def check_last_message(self, msg_regex):
        """
        Get the last alert and search the message for
        regular expression pattern 'msg_regex'.

        :param msg_regex Regular expression pattern matching the message
                         of the last alert.
        :return Return True if alert exists.
        """
        return re.search(msg_regex, self.last_line.text) is not None

    def check_message(self, msg, msg_type):
        """
        Return True if the message string is a substring of any(!)
        found info/error message. Maybe it makes sense to clean up
        the messages with /sa clear_messages.
        :param msg The substring to search for in the open alert boxes
        :param msg_type Specify box type where you expect 'msg'. /sa MsgType
        :return Return True if 'msg' is part of any alert box of 'msg_type'.
        """

        self.parse()
        lines = [l for l in self.info_lines if l.type == msg_type and msg in l.text]

        return len(lines)>0
