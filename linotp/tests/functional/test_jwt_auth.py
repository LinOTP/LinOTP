import logging
from typing import Callable

import pytest
from flask_jwt_extended import create_access_token

from flask.testing import FlaskClient

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

    def test_access_with_correct_jwt(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        client: FlaskClient,
    ) -> None:
        client.post(
            "/admin/login",
            data=dict(
                username="passthru_user1",
                password="geheim1",
            ),
        )

        csrf_token = (
            client.cookie_jar._cookies.get("localhost.local")
            .get("/")["csrf_access_token"]
            .value
        )

        valid_token_req = client.post(
            "/system/getConfig",
            headers={"X-CSRF-TOKEN": csrf_token},
        )

        assert isinstance(valid_token_req.json["result"]["value"], dict)
        assert len(valid_token_req.json["result"]["value"]) > 1
        assert valid_token_req.status_code == 200

    def test_access_with_wrong_jwt(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        client: FlaskClient,
    ) -> None:

        fake_token = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzQ3MTE3MjgsIm5iZ"
            "iI6MTYzNDcxMTcyOCwianRpIjoiOWFkNmQ2ZTctNTU4Zi00ZDY0LThhMGItOGQ1MmY"
            "zYjYwMDA5IiwiZXhwIjo5OTk5OTk5OTk5OTksImlkZW50aXR5Ijp7InVzZXJuYW1lI"
            "joianVzdF9hX2Zha2UifSwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIiwiY3N"
            "yZiI6ImVjMWNlNWQwLTU2M2MtNDM4OS1hOTFlLTcxZDA0MTM5NzJjOCJ9.9n-IZ0S0"
            "8kTAO390CZSwkmk3ugB8_BVyMgFUrNGe4wA"
        )
        client.set_cookie("localhost.local", "access_token_cookie", fake_token)

        invalid_token_req = client.post(
            "/system/getConfig", headers={"X-CSRF-TOKEN": "1234"}
        )

        result = invalid_token_req.json["result"]

        assert result["status"] is False
        assert result["error"]["message"] == "Not authenticated"
        assert invalid_token_req.status_code == 401

    def test_access_with_wrong_csrf(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        client: FlaskClient,
    ) -> None:

        fake_identity = {"username": "any_user"}

        jwt = create_access_token(fake_identity)

        client.set_cookie("localhost.local", "access_token_cookie", jwt)

        invalid_token_req = client.post(
            "/system/getConfig", headers={"X-CSRF-TOKEN": "fake_csrf_token"}
        )

        result = invalid_token_req.json["result"]

        assert result["status"] is False
        assert result["error"]["message"] == "Not authenticated"
        assert invalid_token_req.status_code == 401
