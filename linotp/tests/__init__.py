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
import io
import json
import logging
import os
import warnings
from datetime import datetime
from unittest import TestCase
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from flask import current_app, g, request
from werkzeug.test import TestResponse

from linotp.lib.user import User

warnings.filterwarnings(action="ignore", category=DeprecationWarning)


def fxn():
    warnings.warn("deprecated", DeprecationWarning, stacklevel=1)


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    fxn()

LOG = logging.getLogger("flask.app")

__all__ = ["TestController", "environ", "url"]

environ = {}


def url(controller, action):
    """
    Generate URL for a given controller and action
    """
    if controller.endswith("/"):
        warnings.warn("Controller name should not have a trailing slash", stacklevel=1)
        controller = controller.rpartition("/")[0]

    return "/".join([controller, action or ""]).replace("//", "/")


class CompatibleTestResponse(TestResponse):
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
        g.audit = {}  # ensure `g.audit` exists

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

    @classmethod
    def setup_class(cls):
        return

    @classmethod
    def teardown_class(cls):
        """teardown - cleanup of test class execution result"""
        LOG.info("######## teardown_class: %r", cls)
        return

    @staticmethod
    def delete_cookie(app_client, key):
        """
        Delete a cookie from the test client

        :param client: the flask test client
        :param key: the key of the cookie
        """
        app_client.delete_cookie(".localhost", key)
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
        """here we do the system test init per test method"""
        self.session = "justatest"
        self.resolvers = {}  # Set up of resolvers in create_common_resolvers

        # dict of all authenticated users cookies
        self.user_service = {}

        request.environ["REQUEST_ID"] = str(uuid4())
        request.environ["REQUEST_START_TIMESTAMP"] = datetime.now()

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
                f_param: (io.BytesIO(content.encode("utf-8")), file_name),
            }
            params.update(nparams)
            headers["Content-Type"] = "multipart/form-data"
        if content_type:
            headers["Content-Type"] = content_type
            if content_type == "application/json":
                params = json.dumps(params)

        if client:
            if not headers:
                headers = {}
            headers["REMOTE_ADDR"] = client
            pparams["environ_overrides"] = {"REMOTE_ADDR": client}

        # ------------------------------------------------------------------ --

        if method == "GET":
            response = self.client.get(
                url(controller=controller, action=action),
                query_string=params,
                headers=headers,
                **pparams,
            )
        elif method == "PUT":
            response = self.client.put(
                url(controller=controller, action=action),
                data=params,
                headers=headers,
                **pparams,
            )
        else:
            response = self.client.post(
                url(controller=controller, action=action),
                data=params,
                headers=headers,
                **pparams,
            )

        response.body = response.data.decode("utf-8")
        return response

    @patch("linotp.controllers.base.verify_jwt_in_request", lambda: True)
    @patch("linotp.controllers.base.get_jwt_identity")
    def _make_authenticated_request(
        self,
        app_get_jwt_identity: Mock,
        controller: str | None = None,
        action: str | None = None,
        method=None,
        params=None,
        headers=None,
        auth_user="admin",
        upload_files=None,
        client=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request
        """

        login = auth_user
        resolver = auth_resolver
        realm = current_app.config["ADMIN_REALM_NAME"].lower()

        if isinstance(auth_user, User):
            login = auth_user.login
            realm = auth_user.realm or current_app.config["ADMIN_REALM_NAME"].lower()
            resolver = auth_user.resolver_config_identifier or auth_resolver

        app_get_jwt_identity.return_value = {
            "username": login,
            "resolver": resolver,
            "realm": realm,
        }

        params = params or {}
        headers = headers or {}

        return self.make_request(
            controller,
            action,
            method=method,
            params=params,
            headers=headers,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
        )

    def make_api_v2_request(
        self,
        action,
        params=None,
        method="GET",
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /api/v2/
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="/api/v2",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_admin_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /admin/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="admin",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_audit_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /audit/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="audit",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_manage_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /manage/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="manage",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_system_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /system/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="system",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_reporting_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /reporting/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="reporting",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_monitoring_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /monitoring/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="monitoring",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_gettoken_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
    ):
        """
        Makes an authenticated request to /gettoken/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="gettoken",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
        )

    def make_healthcheck_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
    ):
        """
        Makes an authenticated request to /healthcheck/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="healthcheck",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
        )

    def make_tools_request(
        self,
        action,
        params=None,
        method=None,
        auth_user="admin",
        client=None,
        upload_files=None,
        content_type=None,
        auth_resolver="useridresolver.PasswdIdResolver.IdResolver.myDefRes",
    ):
        """
        Makes an authenticated request to /tools/'action'
        """
        if not params:
            params = {}
        return self._make_authenticated_request(
            controller="tools",
            action=action,
            method=method,
            params=params,
            auth_user=auth_user,
            upload_files=upload_files,
            client=client,
            content_type=content_type,
            auth_resolver=auth_resolver,
        )

    def make_validate_request(self, action, params=None, method=None, client=None):
        """
        Makes an unauthenticated request to /validate/'action'
        """
        if not params:
            params = {}
        return self.make_request(
            "validate", action, method=method, params=params, client=client
        )

    def delete_all_realms(self, auth_user="admin"):
        """get all realms and delete them"""

        _admin_realm = current_app.config["ADMIN_REALM_NAME"].lower()

        response = self.make_system_request("getRealms", params={}, auth_user=auth_user)

        realms = response.json.get("result", {}).get("value", {})

        for realm_name, realm_desc in realms.items():
            if realm_desc["admin"]:
                continue

            params = {"realm": realm_name}
            resp = self.make_system_request(
                "delRealm", params=params, auth_user=auth_user
            )
            assert '"result": true' in resp.body

    def delete_all_resolvers(self, auth_user="admin"):
        """get all resolvers and delete them"""

        default_admin_resolver_name = current_app.config["ADMIN_RESOLVER_NAME"]

        response = self.make_system_request(
            "getResolvers", params={}, auth_user=auth_user
        )
        values = response.json.get("result", {}).get("value", {})

        for resolver_name, resolver_description in values.items():
            # the admin resolvers should not be deleted as they
            # are still in use by the admin realm, which could not be deleted

            if resolver_description["admin"]:
                continue

            # the default admin resolver could not be deleted

            if resolver_name == default_admin_resolver_name:
                continue

            params = {"resolver": resolver_name}
            response = self.make_system_request(
                "delResolver", params=params, auth_user=auth_user
            )
            assert response.json["result"]["value"], response

    def delete_all_policies(self, auth_user="admin"):
        """
        Get all policies and delete them

        special handling for system policies

        """
        response = self.make_system_request(
            action="getPolicy", params={}, auth_user=auth_user
        )
        content = response.json
        err_msg = f"Error getting all policies. Response {content}"
        assert content["result"]["status"], err_msg
        policies = content.get("result", {}).get("value", {})

        # first check which are the system policies with write rigts

        sys_policies = []
        for policy_name, policy_def in list(policies.items()):
            if policy_def["scope"] == "system":
                action = policy_def["action"]
                if "write" in action or "*" in action:
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
        expected_keys = {"name", "scope", "action", "user", "realm", "client", "time"}
        diff_set = expected_keys - set(lparams.keys())
        assert len(diff_set) == 0, (
            f"Some key is missing to create a policy {diff_set!r}"
        )

        response = self.make_system_request("setPolicy", params=lparams)
        content = response.json
        assert content["result"]["status"]
        expected_value = {
            "setPolicy {}".format(params["name"]): {
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
        """delete the current installed license"""

        params = {"key": "license"}
        response = self.make_system_request("delConfig", params)
        msg = '"delConfig license": true'
        assert msg in response

        params = {"key": "license_duration"}
        response = self.make_system_request("delConfig", params)
        msg = '"delConfig license_duration": true'
        assert msg in response

    def delete_config(self, prefix):
        """
        delete config entry with prefix
        """

        response = self.make_system_request("getConfig")

        entries = json.loads(response.body)["result"]["value"]

        for entry in entries:
            if not entry.startswith(prefix):
                continue

            response = self.make_system_request("delConfig", params={"key": entry})

            assert "false" not in response

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
                    f"linotp.Policy.{name}.action": True,
                    f"linotp.Policy.{name}.active": True,
                    f"linotp.Policy.{name}.client": True,
                    f"linotp.Policy.{name}.realm": True,
                    f"linotp.Policy.{name}.scope": True,
                    f"linotp.Policy.{name}.time": True,
                    f"linotp.Policy.{name}.user": True,
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

        err_msg = f"Error getting token list. Response {content}"
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
        err_msg = f"Error deleting token {serial}. Response {content}"
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

    def set_default_realm(self, realm):
        params = {"realm": realm.lower()}
        response = self.make_system_request("setDefaultRealm", params=params)
        return response

    def create_common_realms(self):
        """

        create a set of three realms - if they do not already exist

        Idea: build out of two resolvers
            3 realms
            - 1 per resolver
            - 1 which contains both

        """

        common_realms = {
            "myDefRealm": self.resolvers["myDefRes"],
            "myOtherRealm": self.resolvers["myOtherRes"],
            "myMixRealm": [
                self.resolvers["myDefRes"],
                self.resolvers["myOtherRes"],
            ],
        }

        response = self.make_system_request("getRealms", {})
        existing_realms = response.json["result"]["value"]

        for realm, resolver_definition in common_realms.items():
            # create the realm if it does not already exist

            if realm.lower() not in existing_realms:
                response = self.create_realm(realm=realm, resolvers=resolver_definition)

                content = response.json
                assert content["result"]["status"]
                assert content["result"]["value"]

            # assure that the myDefRealm is the default realm

            if realm.lower() == "myDefRealm".lower():
                params = {"realm": realm.lower()}
                response = self.make_system_request("setDefaultRealm", params=params)

                assert "false" not in response

        # Assert 'myDefRealm' is default

        response = self.make_system_request("getRealms", {})
        content = response.json

        assert content["result"]["status"]
        realms = content["result"]["value"]
        lookup_realm = {"mydefrealm", "mymixrealm", "myotherrealm"}
        assert lookup_realm == set(realms).intersection(lookup_realm)
        assert "mydefrealm" in realms
        assert "default" in realms["mydefrealm"]
        assert realms["mydefrealm"]["default"]

    def _user_service_init(self, auth_user: str, password: str, otp: str | None = None):
        auth_user = auth_user.encode("utf-8")
        password = password.encode("utf-8")

        if otp:
            otp = otp.encode("utf-8")

            passw = (
                base64.b32encode(otp).decode()
                + ":"
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
            self.user_service = {}

        otp = None
        if len(auth_user) == 3:
            user, password, otp = auth_user
        else:
            user, password = auth_user

        if new_auth_cookie and user in self.user_service:
            del self.user_service[user]

        auth_cookie = self.user_service.get(user, None)

        if not auth_cookie:
            response, auth_cookie = self._user_service_init(user, password, otp)

            if not auth_cookie:
                response.body = response.data.decode("utf-8")
                return response

        params["session"] = auth_cookie
        params["user"] = user
        response = self.client.post("/userservice/" + action, data=params)

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
            self.user_selfservice = {}

        auth_cookie = self.user_selfservice.get(user)

        if not auth_cookie:
            response, auth_cookie = self._user_service_login(user, password, otp)

            if not auth_cookie or '"value": false' in response.body:
                response.body = response.data.decode("utf-8")
                return response

            self.user_selfservice[user] = auth_cookie

        params["session"] = auth_cookie
        # params['user'] = user
        response = self.client.post(
            url(controller="userservice", action=action), data=params
        )

        if response.status_code != 200:
            msg = f"Server Error {response.status_code}"
            raise Exception(msg)

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
            self.user_selfservice = {}

        auth_cookie = self.user_selfservice.get(user)

        if not auth_cookie:
            response, auth_cookie = self._user_service_login(user, password, otp)

            if not auth_cookie or '"value": false' in response.body:
                return response

            self.user_selfservice[user] = auth_cookie

        params["session"] = auth_cookie
        # params['user'] = user
        response = self.client.get(
            url(controller="selfservice-legacy", action=action),
            query_string=params,
        )

        response.body = response.data.decode("utf-8")
        return response

    def get_last_audit_entry(self):
        response = self.make_audit_request("search")
        res = response.json
        assert res["rows"]
        return res["rows"][-1]["cell"]

    def get_last_audit_entry_for_action(self, action: str):
        response = self.make_audit_request("search")
        res = response.json
        entries = [row["cell"] for row in res["rows"]]
        filtered_entries = [entry for entry in entries if entry[4] == action]
        return filtered_entries[-1]


# eof #
