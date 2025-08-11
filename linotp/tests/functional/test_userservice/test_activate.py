from . import TestUserserviceController
from .qr_token_validation import QR_Token_Validation as QR

USER = "passthru_user1@myDefRealm"
SERIAL = "qrtoken"
AUTH_USER = (USER, "geheim1")
AUTH_USER2 = ("passthru_user2@myDefRealm", "geheim2")


class TestActivate(TestUserserviceController):
    def setUp(self):
        super().setUp()
        self.token_info, self.secret_key, _ = self.enroll_qr_token()
        self.token_info_other_user, _, _ = self.enroll_qr_token(
            user="passthru_user2@myDefRealm", serial="qrtoken2"
        )
        self.pw_token_serial = self.enroll_pw_token()

    def test_activate_init(self):
        params = {"serial": SERIAL}
        response = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER,
        )
        jresp = response.json
        assert "detail" in jresp
        assert "transactionid" in jresp["detail"]
        # necessary for rendering the qr code in the selfservice
        assert "message" in jresp["detail"]

    def test_activate_init_invalid_token_type(self):
        params = {"serial": SERIAL}
        response = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER,
        )
        jresp = response.json
        assert "detail" in jresp
        assert "transactionid" in jresp["detail"]
        # necessary for rendering the qr code in the selfservice
        assert "message" in jresp["detail"]

    def test_activate_init_invalid_serial(self):
        params = {
            "serial": "notarealserial",
        }
        response = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER,
        )
        assert "detail" not in response.json
        assert not response.json["result"]["value"]

    def test_activate_init_token_from_other_user(self):
        params = {"serial": SERIAL}
        response = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER2,
        )
        assert "detail" not in response.json
        assert not response.json["result"]["value"]

    def test_activate_init_wrong_tokentype(self):
        params = {"serial": self.pw_token_serial}
        response = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER,
        )
        assert "detail" not in response.json
        assert not response.json["result"]["value"]

    def test_activate_check_status(self):
        # GIVEN the user has a QR token for which a valid activation has been triggered
        params = {"serial": SERIAL}
        response_activate = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER,
        )
        detail = response_activate.json.get("detail")
        message = detail.get("message")

        challenge, _, tan = QR.calculate_challenge_response(
            message, self.token_info, self.secret_key
        )
        params = {"transactionid": challenge["transaction_id"], "pass": tan}
        response_check_t = self.make_validate_request("check_t", params)
        assert "false" not in response_check_t

        # WHEN the activation status is checked
        params = {
            "transactionid": response_activate.json["detail"]["transactionid"],
            "use_offline": False,
        }
        response_activate = self.make_userservice_request(
            "activate_check_status",
            params=params,
            auth_user=AUTH_USER,
        )

        # THEN the activation status should indicate success and contain details
        assert "detail" in response_activate.json
        assert response_activate.json["result"]["value"]

    def test_activate_check_status_for_qr_with_pin(self):
        # GIVEN the user has a QR token with a pin for which a valid activation has been triggered
        (token_info, secret_key, _) = self.enroll_qr_token(
            serial="qrtoken_with_pin", pin="asd"
        )
        response_activate = self.make_userservice_request(
            "activate_init",
            params={"serial": "qrtoken_with_pin"},
            auth_user=AUTH_USER,
        )
        message = response_activate.json.get("detail").get("message")
        challenge, _, tan = QR.calculate_challenge_response(
            message, token_info, secret_key
        )
        params = {"transactionid": challenge["transaction_id"], "pass": tan}
        response_check_t = self.make_validate_request("check_t", params)
        assert "false" not in response_check_t

        # WHEN the activation status is checked
        params = {
            "transactionid": response_activate.json["detail"]["transactionid"],
            "use_offline": False,
        }
        response_activate = self.make_userservice_request(
            "activate_check_status",
            params=params,
            auth_user=AUTH_USER,
        )

        # THEN the activation status should indicate success and contain details
        assert "detail" in response_activate.json
        assert response_activate.json["result"]["value"]

    def test_activate_check_status_token_from_other_user(self):
        params = {"serial": SERIAL}
        response = self.make_userservice_request(
            "activate_init",
            params=params,
            auth_user=AUTH_USER,
        )
        params = {
            "transactionid": response.json.get("detail")["transactionid"],
            "use_offline": False,
        }
        response = self.make_userservice_request(
            "activate_check_status",
            params=params,
            auth_user=AUTH_USER2,
        )

        assert "detail" not in response.json
        assert not response.json["result"]["value"]

    def test_activate_check_status_invalid_transid(self):
        params = {
            "transactionid": "invalid_trans_id",
            "use_offline": False,
        }
        response = self.make_userservice_request(
            "activate_check_status",
            params=params,
            auth_user=AUTH_USER,
        )
        assert "detail" not in response.json
        assert not response.json["result"]["value"]
