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
LinOTP application test controller

This package assumes the Flask environment is already loaded by the
calling linotp.app.create_app in , currently assuming the 'testing'

    TestController.create_app(self, config=None)

while the testing configuration could be overwritten

tests are triggerd in the parent directory of the linotp application, e.g. by
`pytest tests/functional/test_one.py`

By using the LinOTP application test api most of the LinOTP functional test
could be ported to the pytest flask by moving the test files into this test
directory.

"""


import base64
import copy
from datetime import datetime
from distutils.version import LooseVersion
import hashlib
import io
import json
import logging
import os
import warnings

from flask import Flask, request, Response
from flask import _request_ctx_stack as flask_request_ctx_stack
from unittest import TestCase
from uuid import uuid4
import pkg_resources
import pytest

from linotp.app import create_app


warnings.filterwarnings(action="ignore", category=DeprecationWarning)


def fxn():
    warnings.warn("deprecated", DeprecationWarning)


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    fxn()

LOG = logging.getLogger('flask.app')

__all__ = ["environ", "url", "TestController"]

environ = {}

def xfail_if_unported(controller, action):
    """
    If a controller is not yet ported, we automatically
    xfail the test if a URL belonging to the controller is
    called. This allows us to see which tests are really
    failing, as opposed to those that use unported URLs
    """
    unported_controllers = [
        'account',
        'custom',
        'error',
        'maintenance',
        'migrate',
        'openid',
        'u2f',
    ]

    if controller in unported_controllers:
        pytest.xfail("Controller %s not yet available (action=%s)" % (controller, action))

def url(controller, action):
    """
    Generate URL for a given controller and action
    """
    if controller.endswith("/"):
        warnings.warn("Controller name should not have a trailing slash")
        controller = controller.strip("/")

    xfail_if_unported(controller, action)
    return "/".join([controller, action or ""])

class CompatibleTestResponse(Response):
    """
    A response class that supports the use of the
    'in' operator for searching the body

    This allows us to port the tests to Pytest without
    needing code changes for code of the form
    'assert foo in response'
    """
    def __contains__(self, value):
        return value in self.body

    def __str__(self, *args, **kwargs):
        return self.body

    def __repr__(self, *args, **kwargs):
        return f"{super().__repr__()} {self.body}"


class ConfigWrapper:
    """
    Compatibility wrapper for old style configuration

    We map old lower case config values to upper case values.
    This is a class so that we can raise warnings later on in
    the porting cycle
    """
    mappings = {
        'sqlalchemy.url': 'SQLALCHEMY_DATABASE_URI',
    }
    def __init__(self, config):
        self.config = config

    def _mapkey(self, key):
        if key in list(self.mappings.keys()):
            return self.mappings[key]
        else:
            return key

    def __getitem__(self, key):
        return self.config[self._mapkey(key)]

    def get(self, key):
        return self.config.get(self._mapkey(key))

class TestController(TestCase):
    """
    the TestController, which loads the linotp app upfront
    """

    DEFAULT_WEB_METHOD = "POST"
    env = {}
    run_state = 0

    session = "justatest"
    resolvers = {}  # Set up of resolvers in create_common_resolvers

    # dict of all autheticated users cookies
    user_service = {}

    fixture_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "functional", "fixtures"
    )

    @pytest.fixture(autouse=True)
    def setup_self_app_and_client(self, app):
        """
        Make the `app` and `client` fixtures available
        as class atributes
        """
        self.app = app

        # Provide a test client instance via class variable
        #
        # In order to work with streamed responses, we need to ensure that all client
        # context is popped once a test has finished. In order to do that, we provide
        # the client within a context manager.
        # For more information see:
        # https://github.com/pytest-dev/pytest-flask/issues/42#issuecomment-188289728
        with app.test_client() as client:
            # Support '<STRING> in response' style tests in client
            client.response_wrapper = CompatibleTestResponse

            self.client = client
            yield

        # Compatibility with Flask on Debian Buster:
        # Older versions of Flask (-> debian buster) do not include the needed code
        # to pop the context if a response was streamed
        # https://github.com/pytest-dev/pytest-flask/issues/42#issuecomment-483864698
        while True:
            top = flask_request_ctx_stack.top
            if top is not None and top.preserved:
                top.pop()
            else:
                break

    @classmethod
    def setup_class(cls):
        return

    @classmethod
    def teardown_class(cls):
        """teardown - cleanup of test class execution result"""
        LOG.info("######## teardown_class: %r" % cls)
        return

    @staticmethod
    def set_cookie(app_client, key, value, expires=None, max_age=None):
        """
        Sets a cookie on the test client

        by setting the expires to 0 and the max_age to 0 the cookie will
        not be valid anymore

        :param client: the flask test client
        :param key: the cookie name
        :param value: the cookie value
        :param expires: the expiration date
        :param max_age: the maximum age of the copkie
        """
        app_client.set_cookie(
            '.localhost', key, value, expires=expires, max_age=max_age)

    @staticmethod
    def delete_cookie(app_client, key):
        """
        Delete a cookie from the test client

        :param client: the flask test client
        :param key: the key of the cookie
        """
        app_client.delete_cookie('.localhost', key)
        return

    @staticmethod
    def get_cookies(response):
        """
        get a cookie from a response

        :return: the cookies dict
        """
        cookies = {}
        cookie_entries = ""
        for entry in response.headers:
            key, val = entry
            if key == "Set-Cookie":
                cookie_entries = val
                break

        cookys = cookie_entries.split(";")

        for cooky in cookys:
            if "=" in cooky:
                cookie_name, cookie_value = cooky.split("=", 1)
                cookies[cookie_name] = cookie_value

        return cookies

    def setUp(self):
        """ here we do the system test init per test method """
        self.session = "justatest"
        self.resolvers = {}  # Set up of resolvers in create_common_resolvers

        # dict of all authenticated users cookies
        self.user_service = {}

        request.environ['REQUEST_ID'] = str(uuid4())
        request.environ['REQUEST_START_TIMESTAMP'] = datetime.now()

        # disable caching as this will change the behavior
        params = {
            "linotp.user_lookup_cache.enabled": True,
            "linotp.resolver_lookup_cache.enabled": True,
        }

        self.make_system_request("setConfig", params=params)

    def tearDown(self):
        # self.delete_all_realms()
        # self.delete_all_resolvers()
        return

    def make_request(
        self,
        controller,
        action,
        method=None,
        params=None,
        headers=None,
        cookies=None,
        client=None,
        upload_files=None,
        content_type=None,
    ):
        """
        Makes a request using WebTest app self.app
        """
        if method is None:
            method = TestController.DEFAULT_WEB_METHOD
        assert controller
        assert method in ["GET", "POST", "PUT"]

        # Clear state (e.g. cookies)
        # self.app.reset()

        pparams = {}

        if upload_files:
            f_param, file_name, content = upload_files[0]
            nparams = {
                f_param: (io.BytesIO(content.encode('utf-8')), file_name),
            }
            params.update(nparams)
            headers["Content-Type"] = 'multipart/form-data'
        if content_type:
            headers['Content-Type'] = content_type
            if content_type == "application/json":
                params = json.dumps(params)

        if client:
            if not headers:
                headers = {}
            headers["REMOTE_ADDR"] = client
            pparams["environ_overrides"] = {"REMOTE_ADDR": client}

        if cookies:
            for key in cookies:
                TestController.set_cookie(self.client, key, cookies[key])

        # ------------------------------------------------------------------ --

        if method == "GET":
            response = self.client.get(
                url(controller=controller, action=action),
                query_string=params,
                headers=headers,
                **pparams
            )
        elif method == "PUT":
            response = self.client.put(
                url(controller=controller, action=action),
                data=params,
                headers=headers,
                **pparams
            )
        else:
            response = self.client.post(
                url(controller=controller, action=action),
                data=params,
                headers=headers,
                **pparams
            )

        response.body = response.data.decode("utf-8")
        return response

    @staticmethod
    def get_http_basic_header(username="admin", method="GET"):
        """
        Returns a string to be used as 'Authorization' in the headers
        dictionary.

        See for full example:
            http://en.wikipedia.org/wiki/Digest_access_authentication
        """
        if method is None:
            method = TestController.DEFAULT_WEB_METHOD

        assert username

        if isinstance(username, tuple):
            login, pw = username
        else:
            login = username
            pw = "randompwd"

        # Authorization: Basic d2lraTpwZWRpYQ==
        auth_info = login + ":" + pw
        return "Basic %s" % str(
            base64.b64encode(auth_info.encode('utf-8')),
            'utf-8')

    @staticmethod
    def get_http_digest_header(username="admin", method="GET"):
        """
        Returns a string to be used as 'Authorization' in the headers
        dictionary. The values contained are basically bogus and we just aim to
        simulate how a real header would look. In production LinOTP we rely on
        Apache2 checking the authorization. In LinOTP only 'Digest username' is
        relevant.

        See for full example:
            http://en.wikipedia.org/wiki/Digest_access_authentication
        """
        if method is None:
            method = TestController.DEFAULT_WEB_METHOD
        assert username
        assert method in ["GET", "POST"]

        # Assuming following 401 response from server:
        # 'www-authenticate': 'Digest realm="LinOTP2 admin area",
        #    nonce="hYJOfgYSBQA=6fd2875a6a04fa4fed643e5e8b0dbcbeed3930ae",
        #    algorithm=MD5, qop="auth"'

        qop = "auth"
        digest_uri = "/random/wont/be/checked"
        nonce = "hYJOfgYSBQA=6fd2875a6a04fa4fed643e5e8b0dbcbeed3930ae"
        password = "randompwd"
        realm = "LinOTP2 admin area"
        nonceCount = "00000001"
        clientNonce = "0a4f113b"
        ha1 = hashlib.md5(
            ("%s:%s:%s" % (username, realm, password)).encode("utf-8")
        ).hexdigest()
        ha2 = hashlib.md5(
            ("%s:%s" % (method, digest_uri)).encode("utf-8")
        ).hexdigest()
        response = hashlib.md5(
            (
                "%s:%s:%s:%s:%s:%s"
                % (ha1, nonce, nonceCount, clientNonce, qop, ha2)
            ).encode("utf-8")
        ).hexdigest()
        auth_content = [
            'Digest username="%s"' % username,
            'realm="%s"' % realm,
            'nonce="%s"' % nonce,
            'uri="%s"' % digest_uri,
            'qop="%s"' % qop,
            'nc="%s"' % nonceCount,
            'cnonce="%s"' % clientNonce,
            'response="%s"' % response,
        ]
        return (", ").join(auth_content)

    def make_authenticated_request(
        self,
        controller,
        action,
        method="GET",
        params=None,
        headers=None,
        cookies=None,
        auth_user="admin",
        upload_files=None,
        client=None,
        auth_type="Digest",
        content_type=None,
    ):
        """
        Makes an authenticated request (setting HTTP Digest header, cookie and
        'session' parameter).
        """
        params = params or {}
        headers = headers or {}
        cookies = cookies or {}
        if "session" not in params:
            params["session"] = self.session

        session = params["session"]

        cookie_name = 'admin_session'
        if controller in ['api/helpdesk']:
            cookie_name = 'helpdesk_session'

        if cookie_name not in cookies:
            cookies[cookie_name] = session

        if "Authorization" not in headers:
            if auth_type == "Basic":
                headers["Authorization"] = TestController.get_http_basic_header(
                    username=auth_user
                )
            else:
                headers[
                    "Authorization"
                ] = TestController.get_http_digest_header(username=auth_user)

        return self.make_request(
            controller,
            action,
            method=method,
            params=params,
            headers=headers,
            cookies=cookies,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
        )

    def make_admin_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        auth_type="Digest",
        content_type=None,
    ):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            "admin",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
            content_type=content_type,
        )

    def make_helpdesk_request(
            self, action, params=None, method=None, headers=None,
            auth_user='helpdesk', client=None, upload_files=None,
            auth_type='Digest', cookies=None, content_type=None):
        """
        Makes an authenticated request to /api/helpdesk/'action'
        """
        if cookies:

            TestController.set_cookie(
                self.client, 'helpdesk_session', cookies.get('helpdesk_session'))

        return self.make_authenticated_request(
            'api/helpdesk',
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
            content_type=content_type
        )

    def make_audit_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        auth_type="Digest",
        content_type=None,
    ):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            "audit",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            client=client,
            auth_type=auth_type,
            content_type=content_type,
        )

    def make_manage_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        auth_type="Digest",
        content_type=None,
    ):
        """
        Makes an authenticated request to /manage/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            "manage",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
            content_type=content_type,
        )

    def make_system_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        auth_type="Digest",
        content_type=None,
    ):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            "system",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
            content_type=content_type,
        )

    def make_reporting_request(self, action, params=None, method=None,
                            auth_user='admin', client=None, upload_files=None,
                            auth_type='Digest',
                            content_type=None):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            'reporting',
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
            content_type=content_type
        )

    def make_gettoken_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        auth_type="Digest",
    ):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            "gettoken",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
        )

    # due to noestests search pattern for test, we have to mangle the name
    # here :(
    def make_t_esting_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
    ):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        res = self.make_authenticated_request(
            "testing",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
        )
        return res

    def make_tools_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        auth_type="Digest",
        content_type=None
    ):
        """
        Makes an authenticated request to /tools/'action'
        """
        if not params:
            params = {}
        return self.make_authenticated_request(
            "tools",
            action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            auth_type=auth_type,
            content_type=content_type,
        )

    def make_validate_request(
        self, action, params=None, method=None, client=None
    ):
        """
        Makes an unauthenticated request to /validate/'action'
        """
        if not params:
            params = {}
        return self.make_request(
            "validate", action, method=method, params=params, client=client
        )

    def set_config_selftest(self, auth_user="admin", unset=False):
        """
        Set selfTest in LinOTP Config to 'True'

        --------------------------------------------------------------------
        | Should not be used and is kept to ease refactoring of old tests. |
        --------------------------------------------------------------------

        'selfTest' mode enables to use the LinOTP API without 'session'
        parameter and cookie, but since using these extra values is not a
        problem and then tests are closer to the real code running on
        productive servers it is preferred NOT to set 'selfTest'.

        Use the methods make_admin_request(), make_system_request or
        make_authenticated_request() and 'session' Parameter and Cookie will be
        set for you!

        All tests that still use set_config_selftest() should be slowly
        refactored to instead use the above mentioned methods.
        """
        if unset:
            params = {"key": "selfTest"}
            response = self.make_system_request(
                "delConfig", params, auth_user=auth_user
            )
            content = response.json
            assert content["result"]["status"]
            assert "delConfig selfTest" in response, response
            self.isSelfTest = False

        else:
            params = {"selfTest": "True"}
            response = self.make_system_request(
                "setConfig", params, auth_user=auth_user
            )
            content = response.json
            assert content["result"]["status"]
            assert "setConfig selfTest:True" in content["result"]["value"]
            assert content["result"]["value"]["setConfig selfTest:True"]
            self.isSelfTest = True

        # *********************************************************************** #
        warnings.warn("The self-test modus is not recommended (anymore)!")

    # *********************************************************************** #

    def delete_all_realms(self, auth_user='admin'):
        """ get al realms and delete them """

        response = self.make_system_request(
            "getRealms", params={}, auth_user=auth_user)

        values = response.json.get("result", {}).get("value", {})

        for realmId in values:
            realm_desc = values.get(realmId)
            realm_name = realm_desc.get("realmname")
            params = {"realm": realm_name}
            resp = self.make_system_request(
                "delRealm", params=params, auth_user=auth_user)
            assert '"result": true' in resp.body

    def delete_all_resolvers(self, auth_user='admin'):
        """ get all resolvers and delete them """

        response = self.make_system_request(
            "getResolvers", params={}, auth_user=auth_user)
        values = response.json.get("result", {}).get("value", {})

        for realmId in values:
            resolv_desc = values.get(realmId)
            resolv_name = resolv_desc.get("resolvername")
            params = {"resolver": resolv_name}
            resp = self.make_system_request(
                "delResolver", params=params, auth_user=auth_user)
            assert '"status": true' in resp.body

    def delete_all_policies(self, auth_user="admin"):
        """
        Get all policies and delete them

        special handling for system policies

        """
        response = self.make_system_request(
            action="getPolicy", params={}, auth_user=auth_user
        )
        content = response.json
        err_msg = "Error getting all policies. Response %s" % (content)
        assert content["result"]["status"], err_msg
        policies = content.get("result", {}).get("value", {})

        # first check which are the system policies with write rigts

        sys_policies = []
        for policy_name, policy_def in list(policies.items()):
            if policy_def['scope'] == 'system':
                action = policy_def['action']
                if 'write' in action or '*' in action:
                    sys_policies.append(policy_name)

        # first delete all non-system policies

        for policy in list(policies.keys()):
            if policy not in sys_policies:
                self.delete_policy(policy, auth_user=auth_user)

        # finally delete the system policies
        for sys_policy in sys_policies:
            self.delete_policy(sys_policy, auth_user=auth_user)

        return

    def create_policy(self, params):
        """
        Create a policy. Following keys are expected in params: name, scope,
        action, user, realm, client and time

        user, realm, client and time can be omitted and will then default to *,
        *, '' and ''
        """
        lparams = {"user": "*", "realm": "*", "client": "", "time": ""}
        lparams.update(params)
        expected_keys = set(
            ["name", "scope", "action", "user", "realm", "client", "time"]
        )
        diff_set = expected_keys - set(lparams.keys())
        assert len(diff_set) == 0, \
            "Some key is missing to create a policy %r" % diff_set

        response = self.make_system_request("setPolicy", lparams)
        content = response.json
        assert content["result"]["status"]
        expected_value = {
            "setPolicy %s"
            % params["name"]: {
                "realm": True,
                "active": True,
                "client": True,
                "user": True,
                "time": True,
                "action": True,
                "scope": True,
            }
        }
        assert expected_value == content["result"]["value"]

    def delete_license(self):
        ''' delete the current installed license '''

        params = {'key': 'license'}
        response = self.make_system_request('delConfig', params)
        msg = '"delConfig license": true'
        assert msg in response

        params = {'key': 'license_duration'}
        response = self.make_system_request('delConfig', params)
        msg = '"delConfig license_duration": true'
        assert msg in response


    def delete_config(self, prefix):
        '''
        delete config entry with prefix
        '''

        response = self.make_system_request('getConfig')

        entries = json.loads(response.body)['result']['value']

        for entry in entries:

            if not entry.startswith(prefix):
                continue

            response = self.make_system_request(
                'delConfig', params={'key': entry})

            assert 'false' not in response

        return

    def delete_policy(self, name, auth_user="admin"):
        """
        Delete the policy with the given name
        """
        assert name, "Policy 'name' can't be empty or None"
        params = {"name": name}
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )
        content = response.json
        expected_value = {
            "delPolicy": {
                "result": {
                    "linotp.Policy.%s.action" % name: True,
                    "linotp.Policy.%s.active" % name: True,
                    "linotp.Policy.%s.client" % name: True,
                    "linotp.Policy.%s.realm" % name: True,
                    "linotp.Policy.%s.scope" % name: True,
                    "linotp.Policy.%s.time" % name: True,
                    "linotp.Policy.%s.user" % name: True,
                }
            }
        }
        assert content["result"]["status"], response
        assert expected_value == content["result"]["value"], response

    def delete_all_token(self):
        """
        Get all token and delete them
        """
        serials = set()

        response = self.make_admin_request("show", params={})
        content = response.json

        err_msg = "Error getting token list. Response %s" % (content)
        assert content["result"]["status"], err_msg
        data = content["result"]["value"]["data"]
        for entry in data:
            serials.add(entry["LinOtp.TokenSerialnumber"])

        for serial in serials:
            self.delete_token(serial)

    def delete_token(self, serial):
        """
        Delete a token identified by its serial number
        """
        assert serial, "serial can not be empty or None"
        params = {"serial": serial}
        response = self.make_admin_request("remove", params=params)
        content = response.json
        err_msg = "Error deleting token %s. Response %s" % (serial, content)
        assert content["result"]["status"], err_msg
        assert 1 == content["result"]["value"], err_msg

    def create_common_resolvers(self):
        """
        Create 2 PasswdIdResolvers named myDefRes and myOtherRes
        """

        resolver_params = {
            "myDefRes": {
                "name": "myDefRes",
                "fileName": (os.path.join(self.fixture_path, "def-passwd")),
                "type": "passwdresolver",
            },
            "myOtherRes": {
                "name": "myOtherRes",
                "fileName": (os.path.join(self.fixture_path, "myDom-passwd")),
                "type": "passwdresolver",
            },
        }
        self.resolvers = {
            "myOtherRes": "useridresolver.PasswdIdResolver.IdResolver.myOtherRes",
            "myDefRes": "useridresolver.PasswdIdResolver.IdResolver.myDefRes",
        }

        for resolver_name in ["myDefRes", "myOtherRes"]:

            # skip definition if resolver is already defined
            response = self.make_system_request("getResolvers")
            if resolver_name in response.body:
                continue

            params = resolver_params[resolver_name]
            response = self.create_resolver(name=resolver_name, params=params)
            content = response.json
            assert content["result"]["status"]
            assert content["result"]["value"]

    def create_resolver(self, name, params):
        param = copy.deepcopy(params)
        param["name"] = name
        resp = self.make_system_request("setResolver", param)
        return resp

    def create_realm(self, realm, resolvers):

        params = {}
        params["realm"] = realm

        if isinstance(resolvers, list):
            params["resolvers"] = ",".join(resolvers)
        else:
            params["resolvers"] = resolvers

        resp = self.make_system_request("setRealm", params)
        return resp

    def create_common_realms(self):
        """

        create a set of three realms - if they do not already exist

        Idea: build out of two resolvers
            3 realms
            - 1 per resolver
            - 1 which contains both

        """

        common_realms = {
            'myDefRealm': self.resolvers['myDefRes'],
            'myOtherRealm': self.resolvers['myOtherRes'],
            'myMixRealm': [self.resolvers['myDefRes'],
                           self.resolvers['myOtherRes']]
            }


        response = self.make_system_request("getRealms", {})
        existing_realms = response.json["result"]["value"]

        for realm, resolver_definition in common_realms.items():

            if realm.lower() in existing_realms:
                continue

            response = self.create_realm(
                realm=realm, resolvers=resolver_definition
            )

            content = response.json
            assert content["result"]["status"]
            assert content["result"]["value"]

        # Assert 'myDefRealm' is default
        response = self.make_system_request("getRealms", {})
        content = response.json

        assert content["result"]["status"]
        realms = content["result"]["value"]
        lookup_realm = set(['mydefrealm', 'mymixrealm', 'myotherrealm'])
        assert lookup_realm == set(realms).intersection(lookup_realm)
        assert "mydefrealm" in realms
        assert "default" in realms["mydefrealm"]
        assert realms["mydefrealm"]["default"]

    def _user_service_init(self, auth_user:str, password:str, otp:str=None):

        auth_user = auth_user.encode('utf-8')
        password = password.encode('utf-8')

        if otp:
            otp = otp.encode('utf-8')

            passw = (
                base64.b32encode(otp).decode() + ":"
                + base64.b32encode(password).decode()
            )
        else:
            passw = ":" + base64.b32encode(password).decode()

        params = {"login": auth_user, "password": passw}
        response = self.client.post(
            url(controller="userservice", action="auth"), data=params
        )

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get("userauthcookie")

        if not auth_cookie:
            return response, None

        self.user_service[auth_user] = auth_cookie

        return response, auth_cookie

    def make_userservice_request(
        self, action, params=None, auth_user=None, new_auth_cookie=False
    ):

        if not params:
            params = {}

        if not hasattr(self, "user_service"):
            setattr(self, "user_service", {})

        otp = None
        if len(auth_user) == 3:
            user, password, otp = auth_user
        else:
            user, password = auth_user

        if new_auth_cookie and user in self.user_service:
            del self.user_service[user]

        auth_cookie = self.user_service.get(user, None)

        if not auth_cookie:
            response, auth_cookie = self._user_service_init(
                user, password, otp)

            if not auth_cookie:
                response.body = response.data.decode("utf-8")
                return response

        TestController.set_cookie(self.client, "userauthcookie", auth_cookie)

        params["session"] = auth_cookie
        params["user"] = user
        response = self.client.get(
            "/userservice/" + action, query_string=params
        )

        response.body = response.data.decode("utf-8")
        return response

    # ---------------------------------------------------------------------- --

    # new selfservice authentication

    def _user_service_login(self, auth_user=None, password=None, otp=None):

        params = {}

        if auth_user is not None:
            params["login"] = auth_user

        if password is not None:
            params["password"] = password

        if otp is not None:
            params["otp"] = otp

        response = self.client.post(
            url(controller="userservice", action="login"), data=params
        )

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get("user_selfservice")

        response.body = response.data.decode("utf-8")
        return response, auth_cookie

    def make_userselfservice_request(
        self, action, params=None, auth_user=None, new_auth_cookie=False
    ):

        if not params:
            params = {}

        # ------------------------------------------------------------------ --

        # identify login credentials

        user = auth_user.get("login")
        password = auth_user.get("password")
        otp = auth_user.get("otp")

        if new_auth_cookie and user in self.user_service:
            del self.user_service[user]

        # ------------------------------------------------------------------ --

        if not hasattr(self, "user_selfservice"):
            setattr(self, "user_selfservice", {})

        auth_cookie = self.user_selfservice.get(user)

        if not auth_cookie:
            response, auth_cookie = self._user_service_login(
                user, password, otp
            )

            if not auth_cookie or '"value": false' in response.body:
                response.body = response.data.decode("utf-8")
                return response

            self.user_selfservice[user] = auth_cookie

        TestController.set_cookie(self.client, "user_selfservice", auth_cookie)

        params["session"] = auth_cookie
        # params['user'] = user
        response = self.client.post(
            url(controller="userservice", action=action), data=params
        )

        if response.status_code != 200:
            raise Exception('Server Error %d' % response.status_code)

        response.body = response.data.decode("utf-8")
        return response

    # ------------------------------------------------------------------------ -

    def make_selfservice_request(
        self, action, params=None, auth_user=None, new_auth_cookie=False
    ):

        if not params:
            params = {}

        # ------------------------------------------------------------------ --

        # identify login credentials

        user = auth_user.get("login")
        password = auth_user.get("password")
        otp = auth_user.get("otp")

        if new_auth_cookie and user in self.user_service:
            del self.user_service[user]

        # ------------------------------------------------------------------ --

        if not hasattr(self, "user_selfservice"):
            setattr(self, "user_selfservice", {})

        auth_cookie = self.user_selfservice.get(user)

        if not auth_cookie:
            response, auth_cookie = self._user_service_login(
                user, password, otp
            )

            if not auth_cookie or '"value": false' in response.body:
                return response

            self.user_selfservice[user] = auth_cookie

        TestController.set_cookie(self.client, "user_selfservice", auth_cookie)

        params["session"] = auth_cookie
        # params['user'] = user
        response = self.client.get(
            url(controller="selfservice", action=action), query_string=params
        )

        response.body = response.data.decode("utf-8")
        return response

# eof #
