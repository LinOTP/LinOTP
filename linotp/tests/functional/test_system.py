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
"""
import logging
import os
from typing import Callable

from mock import Mock, patch

from flask.testing import FlaskClient

from linotp.model.imported_user import ImportedUser
from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestSystemController(TestController):

    # ########################################################################
    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()

    def test_setDefault(self):
        """
        Testing setting default values
        """

        params = {
            "DefaultMaxFailCount": "21",
            "DefaultSyncWindow": "200",
            "DefaultCountWindow": "20",
            "DefaultOtpLen": "8",
            "DefaultResetFailCount": "False",
        }
        response = self.make_system_request(action="setDefault", params=params)
        # log.debug("response %s\n",response)
        assert '"set DefaultSyncWindow": true' in response, response
        assert '"set DefaultMaxFailCount": true' in response, response
        assert '"set DefaultResetFailCount": true' in response, response
        assert '"set DefaultSyncWindow": true' in response, response
        assert '"set DefaultMaxFailCount": true' in response, response
        assert '"set DefaultCountWindow": true' in response, response

        params = {
            "DefaultMaxFailCount": "10",
            "DefaultSyncWindow": "1000",
            "DefaultCountWindow": "10",
            "DefaultOtpLen": "6",
            "DefaultResetFailCount": "True",
        }

        response = self.make_system_request(action="setDefault", params=params)
        # log.info("response %s\n",response)

        assert '"set DefaultSyncWindow": true' in response, response
        assert '"set DefaultMaxFailCount": true' in response, response
        assert '"set DefaultResetFailCount": true' in response, response
        assert '"set DefaultSyncWindow": true' in response, response
        assert '"set DefaultMaxFailCount": true' in response, response
        assert '"set DefaultCountWindow": true' in response, response

    def test_001_resolvers(self):
        """
        setup: delete realms
        """
        self.delete_all_realms()

        params = {"username": "root"}
        response = self.make_admin_request(action="userlist", params=params)

        pass
        params = {"username": "root", "realm": "myMixRealm"}

        response = self.make_admin_request(action="userlist", params=params)

        pass

    def test_001_realms(self):
        """"""
        self.create_common_resolvers()
        self.create_common_realms()
        response = self.make_system_request(action="getRealms")

        # set realms
        assert '"realmname": "mydefrealm"' in response, response
        assert '"realmname": "myotherrealm"' in response, response
        assert '"realmname": "mymixrealm"' in response, response

        # now check for the different users in the different realms
        params = {"username": "root", "realm": "*"}

        response = self.make_admin_request(action="userlist", params=params)

        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myOtherRes"' in response
        ), response
        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myDefRes"' in response
        ), response

        # now check for the different users in the different realms
        params = {"username": "root", "realm": "myDefRealm"}

        response = self.make_admin_request(action="userlist", params=params)
        # log.info("response %s\n",response)

        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myDefRes"' in response
        ), response
        assert '"root-def-passwd"' in response, response

        # now check for the different users in the different realms
        params = {"username": "root", "realm": "myMixRealm"}

        response = self.make_admin_request(action="userlist", params=params)

        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myOtherRes"' in response
        ), response
        assert '"root-myDom-passwd"' in response, response

        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myDefRes"' in response
        ), response
        assert '"root-def-passwd"' in response, response

        # now check for the different users in the different realms
        params = {"username": "root"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)

        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myDefRes"' in response
        ), response
        assert '"root-def-passwd"' in response, response

        # now set default to myDomain
        params = {"realm": "myOtherRealm"}

        response = self.make_system_request(
            action="setDefaultRealm", params=params
        )
        assert '"value": true' in response, response

        response = self.make_system_request(action="getDefaultRealm")
        value = response.json["result"]["value"]
        assert "myotherrealm" in value
        assert "true" in value["myotherrealm"]["default"]

        # now check for the different users in the different realms
        params = {"username": "root"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)

        assert (
            '"useridresolver.PasswdIdResolver.'
            'IdResolver.myOtherRes"' in response
        ), response
        assert '"root-myDom-passwd"' in response, response

        # now delete the default realm
        params = {"realm": "myOtherRealm"}  # check in default

        response = self.make_system_request(action="delRealm", params=params)

        assert '"delRealm": {' in response, response
        assert '"result": true' in response, response

        params = {"realms": "*"}

        response = self.make_system_request(action="getRealms", params=params)
        # set realms
        assert '"realmname": "mydefrealm"' in response, response
        assert '"realmname": "myotherrealm"' not in response, response
        assert '"realmname": "mymixrealm"' in response, response

        # now check for the different users in the different realms
        params = {"username": "def"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)
        value = response.json["result"]["value"]
        assert value == [], response

        # now check for the different users in the different realms
        params = {"username": "def", "realm": "myDefRealm"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)
        # log.info("response %s\n",response)
        assert '"description": "def User,,,,"' in response, response

        # now set default to myDomain
        params = {"realm": "myDefRealm"}

        response = self.make_system_request(
            action="setDefaultRealm", params=params
        )
        assert '"value": true' in response, response

        response = self.make_system_request(action="getDefaultRealm")
        value = response.json["result"]["value"]
        assert "mydefrealm" in value
        assert "true" in value["mydefrealm"]["default"]

        # now check for the different users in the different realms
        params = {"username": "def"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)

        assert '"description": "def User,,,,"' in response, response

        # now set default to myDomain
        params = {"realm": "myMixRealm"}

        response = self.make_system_request(
            action="setDefaultRealm", params=params
        )
        assert '"value": true' in response, response

        response = self.make_system_request(action="getDefaultRealm")
        value = response.json["result"]["value"]
        assert "mymixrealm" in value
        assert "true" in value["mymixrealm"]["default"]

        # now check for the different users in the different realms
        params = {"username": "root"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)

        assert '"root-def-passwd"' in response, response
        assert '"root-myDom-passwd"' in response, response

        # now set default to myDomain
        params = {"realm": "myOtherRealm"}

        response = self.make_system_request(
            action="setDefaultRealm", params=params
        )
        assert '"value": false' in response, response

        response = self.make_system_request(action="getDefaultRealm")
        value = response.json["result"]["value"]
        assert "mymixrealm" in value
        assert "true" in value["mymixrealm"]["default"]

        # now check for the different users in the different realms
        params = {"username": "def", "resConf": "myDefRes"}  # check in default

        response = self.make_admin_request(action="userlist", params=params)
        # log.info("response %s\n",response)
        assert '"description": "def User,,,,"' in response, response
        self.delete_all_realms()
        self.delete_all_resolvers()

    def test_set_default(self):
        """
        System-controller: set default without matching keys
        """
        params = {"wrongKey": "wrongVal"}
        response = self.make_system_request(action="setDefault", params=params)

        assert '"status": false' in response, response
        assert "Usage: setDefault: parameters are" in response, response

    def test_setconfig_backwards(self):
        """
        testing setconfig backward compat
        """
        params = {"key": "test", "value": "old", "description": "old value"}
        response = self.make_system_request(action="setConfig", params=params)

        assert '"setConfig test": true' in response, response

        params = {
            "key": "some.resolver.config",
            "value": "resolverText",
            "description": "resolver test",
        }
        response = self.make_system_request(action="setConfig", params=params)

        assert '"setConfig some.resolver.config": true' in response, response

    def test_setconfig_typing(self):
        """
        Test: system/setConfig with typing
        """
        response = self.make_system_request(action="getConfig")
        assert "secretkey" not in response, response

        params = {"secretkey": "test123", "secretkey.type": "password"}
        response = self.make_system_request(action="setConfig", params=params)
        log.info(response)
        assert '"setConfig secretkey:test123": true' in response, response

        # the value will be returned transparently
        response = self.make_system_request(
            action="getConfig", params={"key": "secretkey"}
        )
        assert "test123" not in response, response

        # the value will be returned transparently
        params = {"key": "enclinotp.secretkey"}
        response = self.make_system_request(action="getConfig", params=params)
        assert "test123" not in response, response

        response = self.make_system_request(
            action="delConfig", params={"key": "secretkey"}
        )
        return

    def test_delResolver(self):
        """
        Testing the deleting of a resolver
        """

        params = {
            "name": "reso1",
            "type": "passwdresolver",
            "fileName": os.path.join(self.fixture_path, "my-pass2"),
        }

        response = self.make_system_request(
            action="setResolver", params=params
        )

        assert '"value": true' in response, response

        params = {
            "name": "reso2",
            "type": "passwdresolver",
            "fileName": os.path.join(self.fixture_path, "my-pass2"),
        }

        response = self.make_system_request(
            action="setResolver", params=params
        )

        assert '"value": true' in response, response
        params = {
            "name": "reso3",
            "type": "passwdresolver",
            "fileName": os.path.join(self.fixture_path, "my-pass2"),
        }

        response = self.make_system_request(
            action="setResolver", params=params
        )

        assert '"value": true' in response, response

        response = self.make_system_request(action="getResolvers", params={})

        assert (
            '"entry": "linotp.passwdresolver.fileName.reso2"' in response
        ), response
        assert (
            '"entry": "linotp.passwdresolver.fileName.reso1"' in response
        ), response
        assert (
            '"entry": "linotp.passwdresolver.fileName.reso3"' in response
        ), response

        # create a realm
        params = {
            "realm": "realm1",
            "resolvers": "passwdresolver.reso1, passwdresolver.reso2",
        }
        response = self.make_system_request(action="setRealm", params=params)

        assert '"value": true' in response, response

        # try to delete a resolver, that is in a realm
        response = self.make_system_request(
            action="delResolver", params={"resolver": "reso1"}
        )

        assert "Resolver 'reso1'  still in use" in response, response

        response = self.make_system_request(
            action="delResolver", params={"resolver": "reso3"}
        )
        assert '"value": true' in response, response

    def test_policy_wrong_name(self):
        """
        testing to set a policy with a wrong name
        """
        params = {
            "name": "ads ads asd",
            "action": "*",
            "scope": "admin",
            "realm": "*",
        }
        response = self.make_system_request(action="setPolicy", params=params)

        assert (
            "The name of the policy may only contain"
            " the characters" in response
        ), response

        self.delete_all_policies()

        return

    def test_bad_policy_name_import(self):

        policy_content = """[ded-ee]
realm = *
active = True
client = ""
user = *
time = ""
action = "otppin=password "
scope = authentication
"""

        upload_files = [("file", "savedPolicy.txt", policy_content)]

        response = self.make_system_request(
            action="importPolicy", params={}, upload_files=upload_files
        )

        assert "<status>False</status>" in response, response
        assert "may only contain the characters" in response, response

        # Now check the policies, that we imported...
        response = self.make_system_request(
            action="getPolicy", method="POST", params={}, auth_user="superuser"
        )

        assert not ("ded-ee" in response), response

        return

    def test_import_policy_empty_realm(self):
        """
        test import of policies with no or empty realm
        """

        # load the policy cfg for import

        policy_file = "policy_realm.cfg"

        file_name = os.path.join(self.fixture_path, policy_file)

        with open(file_name, "r") as f:
            policy_content = f.read()

        upload_files = [("file", policy_file, policy_content)]

        response = self.make_system_request(
            action="importPolicy", params={}, upload_files=upload_files
        )

        assert "<status>True</status>" in response, response

        # Now check the policies, that we imported...

        response = self.make_system_request(
            action="getPolicy", method="POST", params={}, auth_user="superuser"
        )

        assert not ("ded-ee" in response), response

        return

    def test_import_policy(self):

        policy_content = """[resovler_ss1]
realm = realm2
client = None
user = lse_ad:
time = None
action = "webprovisionGOOGLE, "
scope = selfservice
[resovler_ss2]
realm = realm2
client = None
user = "local:, koelbel"
time = None
action = "webprovisionGOOGLEtime, assign, "
scope = selfservice
[ss1_maria]
realm = realm1
client = None
user = maria
time = None
action = "max_count_hotp=10, webprovisionGOOGLE, getotp, enrollYUBICO, "
scope = selfservice
[SMS]
realm = realm1
client = ""
user = ""
time = ""
action = smstext=The OTP value for <serial>: <otp>
scope = authentication
[ss1_raff]
realm = realm1
client = None
user = None
time = None
action = "webprovisionGOOGLE, max_count_hotp=5, getotp, assign, enrollSMS, enrollMOTP, setMOTPPIN, history"
scope = selfservice
[gettoken]
realm = *
client = ""
user = *
time = ""
action = max_count_hotp=50
scope = gettoken
"""

        upload_files = [("file", "savedPolicy.txt", policy_content)]

        response = self.make_system_request(
            action="importPolicy", params={}, upload_files=upload_files
        )

        assert "<status>True</status>" in response, response
        assert "<value>6</value>" in response, response

        # Now check the policies, that we imported...
        response = self.make_system_request(
            action="getPolicy", method="POST", params={}, auth_user="superuser"
        )

        assert '"resovler_ss1": {' in response, response
        assert '"resovler_ss2": {' in response, response
        assert '"ss1_maria": {' in response, response
        assert '"SMS": {' in response, response
        assert '"ss1_raff": {' in response, response
        assert '"gettoken": {' in response, response

        # Now we try to upload with access policies.
        params = {
            "name": "superuser",
            "scope": "system",
            "action": "read,write",
            "realm": "*",
            "user": "superuser",
        }

        response = self.make_system_request(
            action="setPolicy",
            method="POST",
            params=params,
            auth_user="superuser",
        )

        assert '"setPolicy superuser":' in response, response

        params = {
            "name": "readsystem",
            "scope": "system",
            "action": "read",
            "realm": "*",
            "user": "readadmin",
        }
        response = self.make_system_request(
            action="setPolicy",
            method="POST",
            params=params,
            auth_user="superuser",
        )

        assert '"setPolicy readsystem":' in response, response

        # superuser is allowed to import
        upload_files = [("file", "savedPolicy.txt", policy_content)]
        response = self.make_system_request(
            action="importPolicy",
            method="POST",
            params={},
            upload_files=upload_files,
            auth_user="superuser",
        )

        assert "<status>True</status>" in response, response
        assert "<value>6</value>" in response, response

        # readadmin is not allowed to import
        upload_files = [("file", "savedPolicy.txt", policy_content)]
        response = self.make_system_request(
            action="importPolicy",
            method="POST",
            params={},
            upload_files=upload_files,
            auth_user="readadmin",
        )

        assert (
            "Policy check failed. You are not allowed to"
            " write system config" in response
        ), response

        # finally remove all policies
        names = []
        for line in policy_content.split():
            if line[0] == "[":
                name = line.replace("[", "").replace("]", "")
                names.append(name)
        for name in names:
            self.delete_policy(name, auth_user="superuser")

        self.delete_policy("readsystem", auth_user="superuser")
        self.delete_policy("superuser", auth_user="superuser")

        return

    def test_get_policy_def(self):
        """Just verify that the endpoint works"""
        response = self.make_system_request(action="getPolicyDef")

        assert '"status": true' in response, response

    def test_set_license_via_form_upload(
        self, license_filename="demo-lic.pem"
    ):
        """
        Ensure that loading a license file works via form upload.
        """
        demo_license_file = os.path.join(self.fixture_path, license_filename)

        with open(demo_license_file, "r") as license_file:
            demo_license = license_file.read()
        form_files = [("license", "demo-lic.pem", demo_license)]

        response = self.make_system_request(
            action="setSupport",
            upload_files=form_files,
            auth_user="superadmin",
        )

        assert '"status": true' in response, response

    def test_set_license_via_post_body(self, license_filename="demo-lic.pem"):
        """
        Ensure that loading a license file works by sending it in \
        the body of a POST request.
        """
        demo_license_file = os.path.join(self.fixture_path, license_filename)

        with open(demo_license_file, "r") as license_file:
            demo_license = license_file.read()
        params = {"license": demo_license}

        response = self.make_system_request(
            action="setSupport", params=params, auth_user="superadmin"
        )

        assert '"status": true' in response, response

    @patch("linotp.controllers.system.setSupportLicense")
    def test_set_license_fails_if_not_provided(self, mock):
        """
        Ensure that loading a license file fails if no file is supplied.
        """
        response = self.make_system_request(
            action="setSupport",
            upload_files=[],
            params={},
            auth_user="superadmin",
        )
        assert '"status": false' in response, response
        mock.assert_not_called()


class TestSystemControllerExtended:
    def test_delete_resolver(
        self,
        create_managed_resolvers: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        resolver_name = "test_res"
        create_managed_resolvers(
            file_name="def-passwd-plain.csv",
            resolver_name=resolver_name,
            plaintext=False,
        )

        iu = ImportedUser(resolver_name)
        all_users = iu.list_users()

        with scoped_authclient(verify_jwt=False) as client:
            resolver_list = client.post("/system/getResolvers")

        assert len(all_users) > 0
        assert resolver_name in resolver_list.json["result"]["value"]

        # delete resolver

        with scoped_authclient(verify_jwt=False) as client:
            client.post(
                "/system/delResolver", data={"resolver": resolver_name}
            )

        with scoped_authclient(verify_jwt=False) as client:
            resolver_list = client.post("/system/getResolvers")

        all_users = iu.list_users()
        assert len(all_users) == 0
        assert resolver_name not in resolver_list.json["result"]["value"]
