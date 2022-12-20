# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

import logging
import helper
import os
import requests
import re

from operator import methodcaller

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from manage_elements import ManageDialog
from realm import RealmManager
from policy import PolicyManager
from system_config import SystemConfig
from user_id_resolver import UserIdResolverManager
from user_view import UserView
from token_view import TokenView

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

    def _is_url_open(self):
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
        assert self._is_url_open(), \
            'URL %s should end with %s - page not loaded?' % \
            (self.driver.current_url, self.URL)
        self.testcase.assertEquals(self.driver.title, 'Management - LinOTP')

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
        if not self._is_url_open():
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

        alert = self.driver.switch_to_alert()
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
        if not self._is_url_open():
            return False

        try:
            self.testcase.disableImplicitWait()
            element = EC.visibility_of_element_located(
                (By.CSS_SELECTOR, css))(self.driver)
            self.testcase.enableImplicitWait()
        except Exception:
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


class AlertBoxHandler:
    """
    The AlertBoxHandler class allows to check the info/error
    messages on the /manage page thrown by admin actions
       e.g. after creating realms, tokens, etc.
    """

    manageui = None

    msgs_parent_id = 'info_box'
    error_msg_class = 'error_box'
    info_msg_class = 'info_box'
    link_close_all_msgs_class = 'close_all'
    single_msg_ok_button_xpath = "//button[contains(text(),'ok')]"

    def __init__(self, manage_ui):
        """
        Init the AlertBoxHandler
        :param manage_ui Reference to the manage_ui
        """
        self.manageui = manage_ui

    def clear_messages(self):
        """
        Delete all action response messages
        """

        try:
            clear_msgs_button = self.manageui.find_by_class(
                self.link_close_all_msgs_class)
            clear_msgs_button.click()
        except:
            pass

        # seems to be only one or no messages at all
        # Remark: if only one message is visible, there's only an OK button
        # beside the message

        try:
            allButtonsError = self.manageui.find_all_by_css(
                ".error_box > button:nth-child(2)")
            [but.click() for but in allButtonsError]
        except:
            pass

        try:
            allButtonsInfo = self.manageui.find_all_by_css(
                ".info_box > button:nth-child(2)")
            [but.click() for but in allButtonsInfo]
        except:
            pass

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

    def check_last_message(self, msg_regex):
        """
        Get the last alert and search the message for
        regular expression pattern 'msg_regex'.

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

        :param msg_regex Regular expression pattern matching the message
                         of the last alert.
        :return Return True if alert exists.
        """
        try:
            info_box_mother_div = self.manageui.driver.find_element_by_xpath(
                "//*[@id='info_box']")

            child_divs = info_box_mother_div.find_elements_by_tag_name("div")

            for curr_div in reversed(child_divs):
                # We want the last visible alert box
                if(curr_div.is_displayed()):
                    if(re.search(msg_regex, curr_div.text)):
                        return True
                    else:
                        return False

        except:
            return False

    def check_message(self, msg, msg_type):
        """
        Return True if the message string is a substring of any(!)
        found info/error message. Maybe it makes sense to clean up
        the messages with /sa clear_messages.
        :param msg The substring to search for in the open alert boxes
        :param msg_type Specify box type where you expect 'msg'. /sa MsgType
        :return Return True if 'msg' is part of any alert box of 'msg_type'.
        """

        xpath = None
        try:
            if(msg_type == MsgType.Error):
                xpath = "//div[@class='" + self.error_msg_class + \
                    "']//span[contains(text(), '" + msg + "')] "
            else:
                xpath = "//div[@class='" + self.info_msg_class + \
                    "']//span[contains(text(), '" + msg + "')] "

            self.manageui.find_by_xpath(xpath)
            return True
        except:
            return False
