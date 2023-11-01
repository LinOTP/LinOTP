import re

from . import TestPoliciesBase


class TestUpoloadPolicies(TestPoliciesBase):
    def setUp(self):
        self.delete_all_policies(auth_user="superadmin")
        self.delete_all_token()

        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies(auth_user="superadmin")
        self.delete_all_token()

        return TestPoliciesBase.tearDown(self)

    def test_708_tokencount(self):
        """
        Policy 708: Import token into a realm, that is already full. This is done by and admin, who only has rights in this realm. Will fail!
        """

        parameters = {
            "name": "ManageAll",
            "scope": "admin",
            "realm": "*",
            "action": "*",
            "user": "superadmin, Administrator",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )
        assert '"status": true' in response, response

        parameters = {
            "name": "enrollment_01",
            "scope": "enrollment",
            "realm": "myDefRealm",
            "action": "maxtoken=2, tokencount=3, otp_pin_random =4",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert '"status": true' in response, response

        for _i in range(1, 3):
            # The user may not own a third token!
            parameters = {
                "type": "spass",
                "user": "root@myDefRealm",
            }

            auth_user = "superadmin"
            response = self.make_admin_request(
                action="init", params=parameters, auth_user=auth_user
            )

            assert '"status": true' in response, response

        parameters = {
            "name": "realmadmin",
            "scope": "admin",
            "realm": "mydefrealm",
            "user": "realmadmin",
            "action": "import,",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert '"status": true' in response, response

        data = "import0001, 1234123412345\nimport0002, 123412341234"
        params = {"type": "oathcsv"}

        response = self.upload_tokens(
            "oathcsv.csv", data=data, params=params, auth_user="realmadmin"
        )

        assert (
            "The maximum number of allowed tokens in realm" in response
        ), response

        return
