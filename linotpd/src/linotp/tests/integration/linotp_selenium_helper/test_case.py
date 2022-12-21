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
import unittest
import logging
import re
from contextlib import contextmanager
from packaging import version
from flaky import flaky
import time
import urllib3


from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.remote.file_detector import UselessFileDetector

from helper import get_from_tconfig, load_tconfig_from_file
from manage_ui import ManageUi
from validate import Validate
from unittest.case import SkipTest

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


def is_flaky_exception(err, *args):
    """
    In case of some exceptions we
    want to re-run the test case.
    """
    if(issubclass(err[0], AssertionError) or
       issubclass(err[0], TimeoutException) or
       issubclass(err[0], WebDriverException) or
       issubclass(err[0], StaleElementReferenceException)):

        time.sleep(30)
        return True

    return False


@flaky(rerun_filter=is_flaky_exception)
class TestCase(unittest.TestCase):
    """Basic LinOTP TestCase class"""

    implicit_wait_time = 5

    driver = None
    "Selenium driver"

    _linotp_version = None  # LinOTP server version
    _manage = None  # Manage UI

    @classmethod
    def setUpClass(cls):
        """Initializes the base_url and sets the driver -
        called from unit tests"""
        cls.loadClsConfig()
        cls.driver = cls.startDriver()

    @classmethod
    def loadClsConfig(cls, configfile=None):
        if configfile:
            load_tconfig_from_file(configfile)

        cls.http_username = get_from_tconfig(
            ['linotp', 'username'], required=True)
        cls.http_password = get_from_tconfig(
            ['linotp', 'password'], required=True)
        cls.http_host = get_from_tconfig(['linotp', 'host'], required=True)
        cls.http_protocol = get_from_tconfig(
            ['linotp', 'protocol'], default="https")
        cls.http_port = get_from_tconfig(['linotp', 'port'])
        cls.base_url = cls.http_protocol + "://" + cls.http_username + \
            ":" + cls.http_password + "@" + cls.http_host
        if cls.http_port:
            cls.base_url += ":" + cls.http_port

        remote_setting = get_from_tconfig(
            ['selenium', 'remote'], default='False')
        cls.remote_enable = remote_setting.lower() == 'true'
        cls.remote_url = get_from_tconfig(['selenium', 'remote_url'])

        cls.selenium_driver_name = get_from_tconfig(['selenium', 'driver'],
                                                    default="firefox").lower()
        cls.selenium_driver_language = get_from_tconfig(['selenium', 'language'],
                                                        default="en_us").lower()

    @classmethod
    def startDriver(cls):
        """
        Start the Selenium driver ourselves. Used by the integration tests.

        remarks:
        see stackoverflow: How to deal with certificates using Selenium?
          https://stackoverflow.com/questions/24507078/how-to-deal-with-certificates-using-selenium
        """
        def _get_chrome_options():
            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument(
                '--lang=' + cls.selenium_driver_language)
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--allow-insecure-localhost')
            chrome_options.add_argument('--unsafely-treat-insecure-origin-as-secure')
            return chrome_options

        def _get_firefox_profile():
            fp = webdriver.FirefoxProfile()
            fp.set_preference(
                "intl.accept_languages", cls.selenium_driver_language)
            fp.accept_untrusted_certs = True
            return fp

        selenium_driver = cls.selenium_driver_name
        if not cls.remote_enable:
            if selenium_driver == 'chrome':
                try:
                    driver = webdriver.Chrome(
                        chrome_options=_get_chrome_options())
                except WebDriverException, e:
                    logger.error("Error creating Chrome driver. Maybe you need to install"
                                 " 'chromedriver'. If you wish to use another browser please"
                                 " adapt your configuratiion file. Error message: %s" % str(e))
                    raise

            elif selenium_driver == 'firefox':
                driver = webdriver.Firefox(
                    firefox_profile=_get_firefox_profile())
            if driver is None:
                logger.warn("Falling back to Firefox driver.")
                driver = webdriver.Firefox(
                    firefox_profile=_get_firefox_profile())
        else:
            # Remote driver. We need to build a desired capabilities
            # request for the remote instance

            # Map the requested driver to the remote capabilities
            # listed in selenium.webdriver.DesiredCapabilities
            #  e.g. firefox -> FIREFOX

            selenium_driver = selenium_driver.upper()

            try:
                desired_capabilities = getattr(
                    DesiredCapabilities, selenium_driver).copy()
                desired_capabilities['acceptInsecureCerts'] = True
            except AttributeError:
                logger.warning(
                    "Could not find capabilities for the given remote driver %s", selenium_driver)
                desired_capabilities = {'browserName': selenium_driver}

            # Remote driver
            url = cls.remote_url
            if not url:
                url = 'http://127.0.0.1:4444/wd/hub'

            try:
                driver = webdriver.Remote(command_executor=url,
                                          desired_capabilities=desired_capabilities)
            except Exception as e:
                logger.error("Could not start driver: %s", e)
                raise

        return driver

    @classmethod
    def tearDownClass(cls):
        if cls.driver:
            cls.driver.quit()

    def setUp(self):
        self.enableImplicitWait()
        self.disableFileUploadForSendKeys()
        self.verification_errors = []
        self.accept_next_alert = True

    def tearDown(self):
        """Closes the driver and displays all errors"""
        self.assertEqual([], self.verification_errors)

    def disableFileUploadForSendKeys(self):
        self.driver.file_detector = UselessFileDetector()

    def disableImplicitWait(self):
        self.driver.implicitly_wait(0)

    def enableImplicitWait(self):
        self.driver.implicitly_wait(self.implicit_wait_time)

    @contextmanager
    def implicit_wait_disabled(self):
        "Disable implicit wait for the statements in the context manager"
        self.disableImplicitWait()
        yield
        self.enableImplicitWait()

    def find_children_by_id(self, parent_id, element_type='*'):
        """
        Find an element with the given id, and return a list of children. The
        child list can be empty.
        """
        # Retrieve all elements including parent. This bypasses the timeout
        # that would other wise occur
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, parent_id))
        )

        self.disableImplicitWait()
        try:
            elements = WebDriverWait(self.driver, 0).until(
                EC.visibility_of_all_elements_located(
                    (By.XPATH, 'id("%s")//%s' % (parent_id, element_type)))
            )
        except TimeoutException:
            return []
        finally:
            self.enableImplicitWait()

        return elements  # Return elements without the parent

    @property
    def manage_ui(self):
        """
        Return page manager
        """
        if self._manage is None:
            self._manage = ManageUi(self)
        return self._manage

    @property
    def validate(self):
        """
        Return validate helper
        """
        return Validate(self.http_protocol, self.http_host, self.http_port, self.http_username, self.http_password)

    @property
    def realm_manager(self):
        return self.manage_ui.realm_manager

    @property
    def useridresolver_manager(self):
        return self.manage_ui.useridresolver_manager

    @property
    def linotp_version(self):
        "LinOTP server version"
        if self._linotp_version is None:
            self._linotp_version = self.validate.version()
        return self._linotp_version

    def need_linotp_version(self, version_minimum):
        """
        Raise a unittest skip exception if the server version is too old

        :param version: Minimum version. Example: '2.9.1'
        :raises unittest.SkipTest: if the version is too old
        """
        current_AUT_version = self.linotp_version.split('.')
        # Avoid comparisons like below:
        # [u'2', u'10', u'dev2+g2b1b96a'] < ['2', '9', '2'] = True
        filtered_version = []

        for version_part in current_AUT_version:
            # Only in case of a 'pure' number, we want to use for comparison
            matchObj = re.search(r'^\d+$', version_part)
            if(matchObj is not None):
                filtered_version.append(version_part)
                continue

            # Match '10' in '2.10rc3'
            matchObj = re.search(r'^(\d+)', version_part)
            if(matchObj is not None):
                filtered_version.append(matchObj.group(1))
                # In case of a release candidate or beta version,
                # we assume the match is the last relevant entry.
                break

        filtered_version_string = '.'.join(filtered_version)

        if(version.parse(filtered_version_string) <
                version.parse(version_minimum)):
            raise SkipTest(
                'LinOTP version %s (%s) <  %s' % (filtered_version_string,
                                                  self.linotp_version,
                                                  version_minimum))

    def reset_resolvers_and_realms(self, resolver=None, realm=None):
        """
        Clear resolvers and realms. Then optionally create a
        userIdResolver with given data and add it to a realm
        of given name.
        """
        self.realm_manager.clear_realms_via_api()
        self.useridresolver_manager.clear_resolvers_via_api()

        if resolver:
            self.useridresolver_manager.create_resolver(resolver)
            self.useridresolver_manager.close()

            if realm:
                self.realm_manager.open()
                self.realm_manager.create(realm, resolver['name'])
                self.realm_manager.close()
        else:
            assert not realm, "Can't create a realm without a resolver"

    def close_alert_and_get_its_text(self):
        try:
            alert = self.driver.switch_to_alert()
            alert_text = alert.text
            if self.accept_next_alert:
                alert.accept()
            else:
                alert.dismiss()
            return alert_text
        finally:
            self.accept_next_alert = True
