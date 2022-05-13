import io
import os

from flask import current_app

from linotp.lib.user import User
from linotp.tests import TestController


class TestAdminUserPrivilege(TestController):

    ADMIN_REALM = None
    ADMIN_RESOLVER = None

    def setUp(self):
        self.ADMIN_REALM = current_app.config["ADMIN_REALM_NAME"].lower()
        self.ADMIN_RESOLVER = current_app.config["ADMIN_RESOLVER_NAME"]

        self.admin_user = User(
            login="admin",
            realm=self.ADMIN_REALM,
            resolver_config_identifier=self.ADMIN_RESOLVER,
        )
        TestController.setUp(self)
        # clean setup

        self.delete_all_policies(auth_user=self.admin_user)
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)
        self.delete_all_policies(auth_user=self.admin_user)
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

    def import_users(self, file_name="4user.csv", resolver_name=None):
        # ------------------------------------------------------------------ --

        if not resolver_name:
            resolver_name = file_name.strip(".csv")

        # open the csv data and import the users

        user_file = os.path.join(self.fixture_path, file_name)

        with io.open(user_file, "r", encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": resolver_name,
            "dryrun": False,
            "format": "csv",
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )
        assert response.json["result"]["status"]

        return response

    def test_privilege(self):
        """
        verify that the admin policies take the resolver definion into account

        1. create resolvers called "admin_user1" and "admin_user2" via import users
        2. add these resolvers to the admin realm
        3. enroll a token
        4. verify that the admin of "admin_user1" and "admin_user2" resolver can
            disable and enable the token
        5. define the policies which allows the admins of the "admin_user1"
           resolver only to disable tokens
        6. verify that the admin of "admin_user2" resolver still can disable and
           enable tokens and the admin of "admin_user1" resolver only can disable
           and not enable tokens

        step 6. verifies that admin policies take the resolver definion into
        account:
            a policy comparisson on a simple name or realm match would not
            prevent the  "admin_user1" to enable tokens.

        """
        admin_realm = self.ADMIN_REALM

        # 1.a create the "admin_user1" resolver from the 4users.csv via import

        response = self.import_users("4users.csv", "admin_user1")

        params = {"resolver": "admin_user1"}
        response = self.make_system_request("getResolver", params=params)
        assert response.json["result"]["status"]

        _4user_resolver_spec = response.json["result"]["value"]["spec"]

        # 1.b create the "admin_user2" resolver from the 4users.csv via import

        response = self.import_users("4users.csv", "admin_user2")

        params = {"resolver": "admin_user2"}
        response = self.make_system_request("getResolver", params=params)
        assert response.json["result"]["status"]

        _user4_resolver_spec = response.json["result"]["value"]["spec"]

        # 2. add the resolver to admin realm

        # first we need to get the admin realm with its resolvers

        param = {"realm": admin_realm}
        response = self.make_system_request(action="getRealms", params=params)
        assert response.json["result"]["status"]

        resolvers = response.json["result"]["value"][admin_realm][
            "useridresolver"
        ]

        # set the admin realm with the extended list of resolvers

        resolvers.append(_4user_resolver_spec)
        resolvers.append(_user4_resolver_spec)

        params = {"realm": admin_realm, "resolvers": ",".join(resolvers)}
        response = self.make_system_request(
            action="setRealm", params=params, auth_user=self.admin_user
        )
        assert response.json["result"]["status"]

        # 3. enroll a token
        params = {
            "serial": "token1",
            "type": "pw",
            "pin": "otppin",
            "otpkey": "secret",
        }
        response = self.make_admin_request("init", params=params)
        assert response.json["result"]["status"]

        # 4. verify that the admin of "admin_user1" and "admin_user2" resolver can
        #    disable and enable the token

        # 4.a define the users
        _4user_admin = User(
            login="admin",
            realm=admin_realm,
            resolver_config_identifier="admin_user1",
        )

        _user4_admin = User(
            login="admin",
            realm=admin_realm,
            resolver_config_identifier="admin_user2",
        )

        # 4.b run our test vector

        params = {"serial": "token1"}

        test_set = [
            (_4user_admin, "disable", True),
            (_4user_admin, "enable", True),
            (_user4_admin, "disable", True),
            (_user4_admin, "enable", True),
        ]
        for auth_user, action, expected in test_set:
            self.make_admin_request(action, params=params, auth_user=auth_user)
            assert response.json["result"]["status"] is expected

        # 5. define the policies
        all_allowed = {
            "action": "*",
            "active": True,
            "client": "*",
            "realm": "*",
            "scope": "admin",
            "user": "admin_user2:",
            "name": "admin_user2",
        }
        response = self.make_system_request(
            "setPolicy", params=all_allowed, auth_user=self.admin_user
        )
        assert response.json["result"]["status"]

        restricted = {
            "action": "disable",
            "active": "True",
            "client": "*",
            "realm": "*",
            "scope": "admin",
            "user": "*",
            "name": "admin_readonly",
        }
        response = self.make_system_request(
            "setPolicy", params=restricted, auth_user=self.admin_user
        )
        assert response.json["result"]["status"]

        # 6. verify that the admin of "admin_user2" resolver still can disable and
        #   enable tokens and the admin of "admin_user1" resolver only can disable
        #   and not enable tokens

        params = {"serial": "token1"}

        test_set = [
            (_4user_admin, "disable", True),
            (_4user_admin, "enable", False),
            (_user4_admin, "disable", True),
            (_user4_admin, "enable", True),
        ]
        for auth_user, action, expected in test_set:
            response = self.make_admin_request(
                action, params=params, auth_user=auth_user
            )
            assert response.json["result"]["status"] == expected
