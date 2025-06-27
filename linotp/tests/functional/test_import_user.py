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
Testing the import of users, which should generate
- an sql table for the users
- an sql resolver (readonly)
- import the users

during the user import it is checked, if the
- user already exists or
- if it is updated or,
- in case of a former existing user, the user will be deleted

the check is made by a dryrun

- test simple csv import
- create realm, containing the resolver with
  - testconnection
  - userlist
  - update of the resolver parameters

- delete the resolver on test end

"""

import json
import logging
import os
from collections.abc import Callable

from flask import current_app
from sqlalchemy import sql
from sqlalchemy.engine import create_engine
from sqlalchemy.exc import ProgrammingError

from linotp.lib.tools.import_user.SQLImportHandler import (
    LinOTP_DatabaseContext,
    SQLImportHandler,
)
from linotp.model import db
from linotp.model.imported_user import ImportedUser
from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestImportUser(TestController):
    resolver_name = "myresolv"
    target_realm = "myrealm"
    resolver_spec = "useridresolver.SQLIdResolver.IdResolver." + resolver_name

    def setUp(self):
        self.delete_all_realms()
        self.delete_all_policies(auth_user="superadmin")
        self.delete_all_resolvers()
        self.deleteAllUsers()

        TestController.setUp(self)

    def deleteAllUsers(self):
        """
        for the tests, we will drop the imported user table
        """

        sqlconnect = self.app.config.get("DATABASE_URI")
        engine = create_engine(sqlconnect)
        connection = engine.connect()

        # we try to delete the table if it exists

        try:
            dropStr = "DELETE * FROM imported_users;"
            t = sql.expression.text(dropStr)
            connection.execute(t)

        except ProgrammingError as exx:
            log.info("Drop Table failed %r", exx)

        except Exception as exx:
            log.info("Drop Table failed %r", exx)

    def test_import_user(self):
        """
        check that import users will create. update and delete users
        """
        # 1- import empty content
        content = ""
        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": self.resolver_name,
            "dryrun": False,
            "format": "password",
            "delimiter": ",",
            "quotechar": '"',
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        assert '"updated": {}' in response, response
        assert '"created": {}' in response, response

        # 2- import a file with hashed passwords
        def_passwd_file = os.path.join(self.fixture_path, "def-passwd")

        with open(def_passwd_file, encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": self.resolver_name,
            "dryrun": False,
            "format": "password",
            "delimiter": ",",
            "quotechar": '"',
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        assert '"updated": {}' in response, response
        jresp = json.loads(response.body)
        created = jresp.get("result", {}).get("value", {}).get("created", {})
        assert len(created) == 27, response

        # 3- import a file with 4 less users > 4 users will be deleted
        # and 1 user's password has changed --> 1 user will be modified
        def_passwd_changed_file = os.path.join(self.fixture_path, "def-passwd-changed")

        with open(def_passwd_changed_file, encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        jresp = json.loads(response.body)
        assert len(jresp["result"]["value"]["modified"]) == 1, response
        assert len(jresp["result"]["value"]["deleted"]) == 4, response
        assert len(jresp["result"]["value"]["updated"]) == 22, response
        assert '"created": {}' in response, response

    def test_import_user_into_local_admin_resolver(self):
        """Very that it's not possible to overwrite the local admin resolver."""

        local_admin_resolver_name = current_app.config["ADMIN_RESOLVER_NAME"]
        upload_files = [("file", "user_list", "")]
        params = {
            "resolver": local_admin_resolver_name,
            "dryrun": False,
            "format": "password",
            "delimiter": ",",
            "quotechar": '"',
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )
        msg = (
            "default admin resolver LinOTP_local_admins is not allowed to "
            "be overwritten!"
        )

        assert not response.json["result"]["status"]
        assert msg in response.json["result"]["error"]["message"], response

    def test_import_user_dryrun(self):
        """
        check that the dryrun does not import a user
        """

        # ----------------------------------------------------------------- --

        # count all available resolver - the dry run should not
        # create a new one

        response = self.make_system_request("getResolvers", {})
        n_initial_realms = len(response.json["result"]["value"])

        # ----------------------------------------------------------------- --

        # setup the import_users parameters by reading the file 'def-passwd'

        def_passwd_file = os.path.join(self.fixture_path, "def-passwd")

        with open(def_passwd_file, encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": self.resolver_name,
            "dryrun": True,
            "format": "password",
            "delimiter": ",",
            "quotechar": '"',
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        assert response.json["result"]["value"]["updated"] == {}, response
        created = response.json["result"]["value"]["created"]
        assert len(created) == 27, response

        # ----------------------------------------------------------------- --

        # a second dry run should as well not create a resolver

        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": self.resolver_name,
            "dryrun": True,
            "format": "password",
            "delimiter": ",",
            "quotechar": '"',
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        assert response.json["result"]["value"]["updated"] == {}, response
        created = response.json["result"]["value"]["created"]
        assert len(created) == 27, response

        # ----------------------------------------------------------------- --

        # make sure that the resolver has not been created on dryrun

        params = {"resolver": self.resolver_name}
        response = self.make_system_request("getResolver", params=params)
        assert response.json["result"]["value"]["data"] == {}, response

        # make sure that no additional resolver was created on dryrun

        response = self.make_system_request("getResolvers", params={})
        assert len(response.json["result"]["value"]) == n_initial_realms, response

    def test_list_imported_users(self):
        """
        list the csv imported users in testresolver and with admin userlist
        """

        # ------------------------------------------------------------------ --

        # open the csv data and import the users

        def_passwd_file = os.path.join(self.fixture_path, "def-passwd.csv")

        with open(def_passwd_file, encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]

        column_mapping = {
            "username": 0,
            "userid": 1,
            "surname": 2,
            "givenname": 3,
            "email": 4,
            "phone": 5,
            "mobile": 6,
            "password": 7,
        }

        params = {
            "resolver": self.resolver_name,
            "dryrun": False,
            "format": "csv",
            "delimiter": ",",
            "quotechar": '"',
            "column_mapping": json.dumps(column_mapping),
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        assert '"updated": {}' in response, response

        jresp = json.loads(response.body)
        created = jresp.get("result", {}).get("value", {}).get("created", {})
        assert len(created) == 24, response

        # ------------------------------------------------------------------ --

        # run a testresolver, if the users are really there

        params = {"resolver": self.resolver_name}
        response = self.make_system_request("getResolver", params=params)
        jresp = json.loads(response.body)

        resolver_params = jresp.get("result", {}).get("value", {}).get("data", {})

        resolver_params["Password"] = ""
        resolver_params["type"] = "sqlresolver"
        resolver_params["name"] = self.resolver_name
        resolver_params["previous_name"] = self.resolver_name
        response = self.make_admin_request("testresolver", params=resolver_params)

        jresp = json.loads(response.body)
        rows = jresp.get("result", {}).get("value", {}).get("desc", {}).get("rows", {})

        assert rows == 24, jresp

        # ------------------------------------------------------------------ --

        # create a realm for this resolver and do a userlist

        params = {"realm": "myrealm", "resolvers": self.resolver_spec}
        response = self.make_system_request(action="setRealm", params=params)

        resolver_id = self.resolver_spec.split(".")[-1]
        params = {"resConf": resolver_id, "username": "*"}
        response = self.make_admin_request(action="userlist", params=params)

        jresp = json.loads(response.body)
        users = jresp.get("result", {}).get("value", [])
        assert len(users) == 24, users

        # ------------------------------------------------------------------ --

        # login to the selfservice and enroll an HMAC token

        policy = {
            "name": "T1",
            "action": "enrollHMAC",
            "user": "*",
            "realm": "*",
            "scope": "selfservice",
        }

        response = self.make_system_request("setPolicy", params=policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ("passthru_user1@" + self.target_realm, "geheim1")

        params = {"type": "hmac", "genkey": "1", "serial": "hmac123"}
        response = self.make_userservice_request(
            "enroll", params=params, auth_user=auth_user
        )
        jresp = json.loads(response.body)
        img = jresp.get("detail", {}).get("enrollment_url", {}).get("img", "")

        assert "data:image" in img, response

        # test for deprecated googleurl
        img = jresp.get("detail", {}).get("googleurl", {}).get("img", "")
        assert "data:image" in img, response

    def test_import_user_policy(self):
        """
        check that import users is policy protected
        """

        policy = {
            "name": "user_import",
            "action": "import_users",
            "user": "hans",
            "realm": "*",
            "scope": "tools",
        }

        response = self.make_system_request("setPolicy", params=policy)

        assert '"status": true' in response

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": self.resolver_name,
            "dryrun": False,
            "format": "password",
            "delimiter": ",",
            "quotechar": '"',
        }

        msg = (
            "You do not have the administrative right to manage tools."
            " You are missing a policy scope=tools, action=import_users"
        )

        response = self.make_tools_request(
            action="import_users",
            params=params,
            upload_files=upload_files,
        )

        assert msg in response, response

        response = self.make_tools_request(
            action="import_users",
            params=params,
            upload_files=upload_files,
            auth_user="hans",
        )

        assert msg not in response, response
        assert '"updated": {}' in response, response
        assert '"created": {}' in response, response

    def test_imported_with_plain_passwords(self):
        """
        list the csv imported users with plain passwords
        """

        # ------------------------------------------------------------------ --

        # 1-open the csv data and import the users

        def_passwd_file = os.path.join(self.fixture_path, "def-passwd-plain.csv")

        with open(def_passwd_file, encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]

        column_mapping = {
            "username": 0,
            "userid": 1,
            "surname": 2,
            "givenname": 3,
            "email": 4,
            "phone": 5,
            "mobile": 6,
            "password": 7,
        }

        params = {
            "resolver": self.resolver_name,
            "passwords_in_plaintext": True,
            "dryrun": False,
            "format": "csv",
            "delimiter": ",",
            "quotechar": '"',
            "column_mapping": json.dumps(column_mapping),
        }

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )

        # check nothing is updated
        assert '"updated": {}' in response, response

        jresp = json.loads(response.body)
        created = jresp.get("result", {}).get("value", {}).get("created", {})
        assert len(created) == 24, response

        # 2-upload one more times to check for update and not modified

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )
        # check nothing is modified
        assert '"modified": {}' in response, response

        jresp = json.loads(response.body)
        updated = jresp.get("result", {}).get("value", {}).get("updated", {})
        assert len(updated) == 24, response

        # 3- upload with changes and check if it gets modified
        # this file is different from the def-passwd-plain in:
        # 00- root pass is changed --> will be modified
        # 01- localuser is renamed to localuser 2--> will be modified
        # 10- user hors removed  3--> will be removed
        def_passwd_changed_file = os.path.join(
            self.fixture_path, "def-passwd-plain-changed.csv"
        )

        with open(def_passwd_changed_file, encoding="utf-8") as f:
            content_changed = f.read()
        upload_files = [("file", "user_list", content_changed)]

        response = self.make_tools_request(
            action="import_users", params=params, upload_files=upload_files
        )
        jresp = json.loads(response.body)
        assert len(jresp["result"]["value"]["modified"]) == 2, response
        assert len(jresp["result"]["value"]["deleted"]) == 1, response
        assert len(jresp["result"]["value"]["updated"]) == 21, response
        assert '"created": {}' in response

        # 4- login to the selfservice to check the password
        policy = {
            "name": "T1",
            "action": "enrollHMAC",
            "user": "*",
            "realm": "*",
            "scope": "selfservice",
        }

        response = self.make_system_request("setPolicy", params=policy)

        setRealmParams = {"realm": "newrealm", "resolvers": self.resolver_spec}

        response = self.make_system_request(action="setRealm", params=setRealmParams)

        # for passthru_user1 do check if policy is defined
        auth_user = ("root", "rootpass")

        params = {"type": "hmac", "genkey": "1", "serial": "hmac123"}
        response = self.make_userservice_request(
            "enroll", params=params, auth_user=auth_user
        )
        jresp = json.loads(response.body)
        img = jresp.get("detail", {}).get("enrollment_url", {}).get("img", "")

        assert "data:image" in img, response

        # test for deprecated googleurl
        img = jresp.get("detail", {}).get("googleurl", {}).get("img", "")
        assert "data:image" in img, response

    def test_import_user_requires_system_write(self):
        """Verify that we require system:write permission to import users."""

        # setup the admin and superadmin system policies

        params = {
            "name": "superadmin_rights",
            "scope": "system",
            "realm": "*",
            "action": "*",
            "user": "superadmin",
        }

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user="superadmin"
        )
        self.assertTrue('"status": true' in response, response)

        params = {
            "name": "admin_rights",
            "scope": "system",
            "realm": "*",
            "action": "read",
            "user": "admin",
        }

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user="superadmin"
        )
        self.assertTrue('"status": true' in response, response)

        # setup the tools policy

        params = {
            "name": "tools_permission",
            "scope": "tools",
            "realm": "*",
            "action": "import_users, *",
            "user": "*",
        }

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user="superadmin"
        )
        self.assertTrue('"status": true' in response, response)

        # verify that admin cannot import users

        try:
            def_passwd_file = os.path.join(self.fixture_path, "def-passwd")

            with open(def_passwd_file) as f:
                content = f.read()

            upload_files = [("file", "user_list", content)]
            params = {
                "resolver": self.resolver_name,
                "dryrun": False,
                "format": "password",
                "delimiter": ",",
                "quotechar": '"',
            }

            response = self.make_tools_request(
                action="import_users",
                params=params,
                upload_files=upload_files,
                auth_user="admin",
            )

            jresp = json.loads(response.body)
            msg = "You are not allowed to write"
            assert msg in jresp["result"]["error"]["message"]

            # verify that superadmin can import users

            response = self.make_tools_request(
                action="import_users",
                params=params,
                upload_files=upload_files,
                auth_user="superadmin",
            )

            jresp = json.loads(response.body)
            assert jresp["result"]["status"]
            assert "error" not in jresp["result"]

        finally:
            # cleanup the sysadmin policies, which will fail
            # by delete_all_policies

            for policy in [
                "tools_permission",
                "admin_rights",
                "superadmin_rights",
            ]:
                self.delete_policy(policy, auth_user="superadmin")

            self.delete_all_policies(auth_user="superadmin")


class TestImportUserExtended:
    def test_delete_by_id(
        self,
        create_common_resolvers: Callable,
    ) -> None:
        username = "nimda"
        database_context = LinOTP_DatabaseContext(
            SqlSession=db.session, SqlEngine=db.engine
        )

        ih = SQLImportHandler(
            groupid="LinOTP_local_admins",
            resolver_name="LinOTP_local_admins",
            database_context=database_context,
        )

        session = database_context.get_session()
        userids = [user.userid for user in session.query(ImportedUser).all()]

        assert username in userids
        ih.delete_by_id(username)

        session.commit()

        userids = [user.userid for user in session.query(ImportedUser).all()]

        assert username not in userids
