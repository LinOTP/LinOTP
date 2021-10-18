import logging
from typing import Callable

import pytest
from flask_jwt_extended import create_access_token

from flask.testing import FlaskClient

from linotp.app import LinOTPApp

log = logging.getLogger(__name__)


class TestJwtAdmin:
    @pytest.mark.parametrize(
        "username,password,expected_message,expected_http_status,expected_status",
        [
            (
                "passthru_user1",
                "geheim1",
                "Login successful for passthru_user1",
                200,
                True,
            ),
            (
                "passthru_user1@def_realm",
                "wrong_password",
                "Bad username or password",
                401,
                False,
            ),
            (
                "wrong_user",
                "wrong_password",
                "Bad username or password",
                401,
                False,
            ),
        ],
    )
    def test_admin_login_with_credentials(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        client: FlaskClient,
        username: str,
        password: str,
        expected_message: str,
        expected_http_status: int,
        expected_status: bool,
    ) -> None:

        res = client.post(
            "/admin/login", data=dict(username=username, password=password)
        )

        assert res.json["result"]["value"] == expected_status
        assert res.status_code == expected_http_status
        assert res.json["detail"]["message"] == expected_message
