import logging
from datetime import datetime, timedelta
from typing import Callable, Optional

import pytest
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
        cookie = next(
            (
                cookie.value
                for cookie in client._cookies.values()
                if (cookie.key == cookie_name) & (cookie.domain == "localhost")
            ),
            None,
        )

        return cookie

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
        res = client.post("/system/getConfig", headers={"X-CSRF-TOKEN": csrf_token})

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
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            client.post(
                "/admin/login",
                data=dict(
                    username="admin",
                    password="Test123!",
                ),
            )

            response = self.do_authenticated_request(client)

            assert isinstance(response.json["result"]["value"], dict)
            assert len(response.json["result"]["value"]) > 1
            assert response.status_code == 200

    def test_access_with_wrong_jwt(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            fake_token = (
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzQ3MTE3Mjgs"
                "Im5iZiI6MTYzNDcxMTcyOCwianRpIjoiOWFkNmQ2ZTctNTU4Zi00ZDY0LThhM"
                "GItOGQ1MmYzYjYwMDA5IiwiZXhwIjo5OTk5OTk5OTk5OTksImlkZW50aXR5Ij"
                "p7InVzZXJuYW1lIjoianVzdF9hX2Zha2UifSwiZnJlc2giOmZhbHNlLCJ0eXB"
                "lIjoiYWNjZXNzIiwiY3NyZiI6ImVjMWNlNWQwLTU2M2MtNDM4OS1hOTFlLTcx"
                "ZDA0MTM5NzJjOCJ9.9n-IZ0S08kTAO390CZSwkmk3ugB8_BVyMgFUrNGe4wA"
            )
            client.set_cookie(
                "access_token_cookie", fake_token, domain="localhost.local"
            )

            response = self.do_authenticated_request(client)

            result = response.json["result"]

            assert result["status"] is False
            assert result["error"]["message"] == "Not authenticated"
            assert response.status_code == 401

    def test_access_with_faulty_jwt(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
        caplog,
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            faulty_token = "faulty_jwt"
            client.set_cookie("access_token_cookie", faulty_token, domain="localhost")

            with caplog.at_level(logging.ERROR):
                response = self.do_authenticated_request(client)
            assert f"jwt_check: could not decode JWT: '{faulty_token}'" in caplog.text

            result = response.json["result"]

            assert result["status"] is False
            assert result["error"]["message"] == "Not authenticated"
            assert response.status_code == 401

    def test_access_with_wrong_csrf(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            client.post(
                "/admin/login",
                data=dict(
                    username="admin",
                    password="Test123!",
                ),
            )

            response = client.post(
                "/system/getConfig",
                headers={"X-CSRF-TOKEN": "fake_csrf_token"},
            )

            result = response.json["result"]

            assert result["status"] is False
            assert result["error"]["message"] == "Not authenticated"
            assert response.status_code == 401

    def test_no_auth_render_login(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            response = client.post("/manage/login")
            data = response.data.decode("utf-8")

            assert response.status_code == 200
            assert "<title>Management Login - LinOTP</title>" in data
            assert '<input type="text" id="username"' in data
            assert '<input type="password" id="password"' in data

    def test_no_auth_redirect_login(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        """
        Formerly this test was used to verify that an authenticated request
        to /manage/(index) endpoint will redirect (status 302) to
        manage/login page which is now no more triggered. Thus the status code
        now is adjusted to be 200.
        """

        with scoped_authclient(verify_jwt=True) as client:
            response = client.get("/manage/")

            assert response.status_code == 200

    def test_redirect_manage(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            client.post(
                "/admin/login",
                data=dict(
                    username="admin",
                    password="Test123!",
                ),
            )

            csrf_token = self.extract_cookie(client, "csrf_access_token")

            response = client.get(
                "/manage/login",
                headers={"X-CSRF-TOKEN": csrf_token},
            )

            assert response.status_code == 200

    def test_render_manage_when_authenticated(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            client.post(
                "/admin/login",
                data=dict(
                    username="admin",
                    password="Test123!",
                ),
            )

            csrf_token = self.extract_cookie(client, "csrf_access_token")

            response = client.get(
                "/manage/",
                headers={"X-CSRF-TOKEN": csrf_token},
            )

            data = response.data.decode("utf-8")

            assert response.status_code == 200
            assert "<title>Management - LinOTP</title>" in data

    def test_get_manage_context_when_authenticated(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        """
        test for the new /manage/context api, which should return
        information about the loged in user.
        """
        with scoped_authclient(verify_jwt=True) as client:
            client.post(
                "/admin/login",
                data=dict(
                    username="admin",
                    password="Test123!",
                ),
            )

            csrf_token = self.extract_cookie(client, "csrf_access_token")

            response = client.get(
                "/manage/context",
                headers={"X-CSRF-TOKEN": csrf_token},
            )

            user = response.json["detail"]["user"]
            assert user["username"] == "admin"
            assert "resolver" in user

    def test_get_manage_context_when_not_authenticated(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        """
        test for the new /manage/context api, which should return
        information about the loged in user - but only if authenticated!
        """

        with scoped_authclient(verify_jwt=True) as client:
            response = client.get(
                "/manage/context",
            )

            assert response.status_code == 401
            assert not response.json["result"]["status"]

    def test_delete_cookies_on_logout(
        self,
        create_common_resolvers: Callable,
        create_common_realms: Callable,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        with scoped_authclient(verify_jwt=True) as client:
            client.post(
                "/admin/login",
                data=dict(
                    username="admin",
                    password="Test123!",
                ),
            )

            csrf_token_saved = self.extract_cookie(client, "csrf_access_token")
            access_token_saved = self.extract_cookie(client, "access_token_cookie")

            assert csrf_token_saved is not None
            assert access_token_saved is not None

            client.get("/admin/logout")

            csrf_token = self.extract_cookie(client, "csrf_access_token")
            access_token = self.extract_cookie(client, "access_token_cookie")

            assert csrf_token is None
            assert access_token is None

            # After logout the jwt token should be blocklisted in order to
            # prevet anyone from recycling it.
            client.set_cookie(
                "access_token_cookie",
                access_token_saved,
                domain="localhost.local",
            )
            client.set_cookie(
                "csrf_access_token", csrf_token_saved, domain="localhost.local"
            )

            hacked_response = self.do_authenticated_request(client)
            # with implementation of blocklist, this should fail now
            hacked_response.json["msg"] = "Token has been revoked"

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
            initial_time = datetime(year=2021, month=10, day=19, hour=17, minute=39)
            with freeze_time(initial_time) as frozen_time:
                client.post(
                    "/admin/login",
                    data=dict(username=username, password=password),
                )

                expiry_time = base_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
                epsilon_t = 5
                frozen_time.tick(delta=timedelta(seconds=expiry_time + epsilon_t))

                response = self.do_authenticated_request(client)

                assert response.status_code == 401, "Jwt token should have expired"

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
                    delta=timedelta(seconds=expiry_time - refresh_time + t_epsilon)
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
        initial_time = datetime(year=2021, month=10, day=19, hour=17, minute=39)
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
                    delta=timedelta(seconds=expiry_time - refresh_time - epsilon_t)
                )

                self.do_authenticated_request(client)

                second_cookie = self.extract_cookie(
                    client,
                    "access_token_cookie",
                )

                assert initial_cookie is second_cookie, (
                    "The JWT cookie should not have been refreshed"
                )
