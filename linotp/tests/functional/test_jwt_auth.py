from datetime import datetime, timedelta
from typing import Callable, Optional

import pytest
from flask_jwt_extended import create_access_token
from freezegun import freeze_time

from flask import Response
from flask.testing import FlaskClient

from linotp.app import LinOTPApp


class TestJwtAdmin:
    def extract_cookie(
        self,
        client: FlaskClient,
        cookie_name: str,
    ) -> Optional[str]:

        cookies = client.cookie_jar._cookies.get("localhost.local").get("/")

        if cookie_name in cookies:
            return cookies[cookie_name].value
        else:
            return None

    def do_authenticated_request(self, client: FlaskClient) -> Response:
        """Calls `/admin/show` which requires a valid session

        Args:
            client (FlaskClient):
                the client which is used for the request

        Returns:
            Response:
                The response object to the request
        """

        csrf_token = self.extract_cookie(client, "csrf_access_token")
        res = client.post("/admin/show", headers={"X-CSRF-TOKEN": csrf_token})

        return res

    @pytest.mark.parametrize(
        "username,password,expected_message,expected_http_status,expected_status",
        [
            (
                "admin",
                "Test123!",
                "Login successful for admin",
                200,
                True,
            ),
            (
                "root@adomain",
                "Test123!",
                "Login successful for root@adomain",
                200,
                True,
            ),
            (
                "admin",
                "wrong_password",
                "Bad username or password",
                401,
                False,
            ),
            (
                "nonexisting_user",
                "wrong_password",
                "Bad username or password",
                401,
                False,
            ),
            (  # correct user and password of a non-admin realm
                "passthru_user1",
                "geheim1",
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
                username="admin",
                password="Test123!",
            ),
        )

        csrf_token = self.extract_cookie(
            client=client, cookie_name="csrf_access_token"
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

    def test_expiration(
        self,
        base_app: LinOTPApp,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient,
    ) -> None:

        username = "admin"
        password = "Test123!"
        with scoped_authclient(verify_jwt=True) as client:
            initial_time = datetime(
                year=2021, month=10, day=19, hour=17, minute=39
            )
            with freeze_time(initial_time) as frozen_time:

                client.post(
                    "/admin/login",
                    data=dict(username=username, password=password),
                )

                expiry_time = base_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
                epsilon_t = 5
                frozen_time.tick(
                    delta=timedelta(seconds=expiry_time + epsilon_t)
                )

                response = self.do_authenticated_request(client)

                assert (
                    response.status_code == 401
                ), "Jwt token should have expired"

    def test_refresh(
        self,
        base_app: LinOTPApp,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient,
    ) -> None:

        username = "admin"
        password = "Test123!"
        initial_time = datetime(year=2021, month=10, day=18, hour=12)
        refresh_time = base_app.config["JWT_ACCESS_TOKEN_REFRESH"]
        expiry_time = base_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
        t_epsilon = 5

        with scoped_authclient(verify_jwt=True) as client:

            with freeze_time(initial_time) as frozen_time:

                client.post(
                    "/admin/login",
                    data=dict(username=username, password=password),
                )

                initial_cookie = self.extract_cookie(
                    client,
                    "access_token_cookie",
                )

                # after this time the token should already get refreshed
                frozen_time.tick(
                    delta=timedelta(
                        seconds=expiry_time - refresh_time + t_epsilon
                    )
                )

                self.do_authenticated_request(client)

                second_cookie = self.extract_cookie(
                    client,
                    "access_token_cookie",
                )

                assert initial_cookie is not second_cookie

    def test_no_unnecessary_refresh(
        self,
        base_app: LinOTPApp,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient,
    ) -> None:

        username = "admin"
        password = "Test123!"
        initial_time = datetime(
            year=2021, month=10, day=19, hour=17, minute=39
        )
        refresh_time = base_app.config["JWT_ACCESS_TOKEN_REFRESH"]
        expiry_time = base_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
        epsilon_t = 5

        with scoped_authclient(verify_jwt=True) as client:
            with freeze_time(initial_time) as frozen_time:

                client.post(
                    "/admin/login",
                    data=dict(username=username, password=password),
                )

                initial_cookie = self.extract_cookie(
                    client,
                    "access_token_cookie",
                )

                frozen_time.tick(
                    delta=timedelta(
                        seconds=expiry_time - refresh_time - epsilon_t
                    )
                )

                self.do_authenticated_request(client)

                second_cookie = self.extract_cookie(
                    client,
                    "access_token_cookie",
                )

                assert (
                    initial_cookie is second_cookie
                ), "The JWT cookie should not have been refreshed"
