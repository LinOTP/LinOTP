from typing import Callable

from flask.testing import FlaskClient

from linotp.app import LinOTPApp
from linotp.model.local_admin_user import LocalAdminResolver


class TestDeleteRealmAndResolver:
    def test_delete_local_admin_resolver_successful(
        self,
        create_common_resolvers: Callable,
        client: FlaskClient,
        base_app: LinOTPApp,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        """
        Testing the deleting of the local admin resolver
        """

        # add the myDefRes resolver to the local admin realm
        realm_name = base_app.config["ADMIN_REALM_NAME"].lower()
        admin_resolver_name = base_app.config["ADMIN_RESOLVER_NAME"]
        admin_resolver_spec = (
            f"useridresolver.SQLIdResolver.IdResolver.{admin_resolver_name}"
        )
        default_resolver_spec = (
            "useridresolver.PasswdIdResolver.IdResolver.def_resolver"
        )

        resolver_classes = f"{admin_resolver_spec},{default_resolver_spec}"

        with scoped_authclient(verify_jwt=False) as client:
            client.post(
                "/system/setRealm",
                data=dict(
                    realm=realm_name,
                    resolvers=resolver_classes,
                ),
            )

        # add a local admin
        LocalAdminResolver(base_app).add_user("test", "test")

        # login as user from realm myDefRes to get the cookies
        client.post(
            "/admin/login",
            data=dict(username="user1", password="geheim1"),
        )

        cookies = client.cookie_jar._cookies["localhost.local"]["/"]

        # extract csrf token
        csrf_token = cookies["csrf_access_token"].value

        # remove local admin resolver
        response = client.post(
            "/system/setRealm",
            headers={"X-CSRF-TOKEN": csrf_token},
            query_string={
                "realm": realm_name,
                "resolvers": default_resolver_spec,
            },
        )

        assert response.json.get("result", {})["status"]
        assert response.json.get("result", {})["value"]

        response = client.post(
            "/system/getRealms",
            headers={"X-CSRF-TOKEN": csrf_token},
        )

        resolvers_in_realm = response.json["result"]["value"][realm_name][
            "useridresolver"
        ]

        assert default_resolver_spec in resolvers_in_realm
        assert admin_resolver_spec not in resolvers_in_realm

    def test_delete_local_admin_resolver_unsuccessful(
        self,
        create_common_resolvers: Callable,
        client: FlaskClient,
        base_app: LinOTPApp,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        """
        Testing the deleting of the local admin resolver
        """

        # add the myDefRes resolver to the local admin realm
        realm_name = base_app.config["ADMIN_REALM_NAME"].lower()
        admin_resolver_name = base_app.config["ADMIN_RESOLVER_NAME"]
        admin_resolver_spec = (
            f"useridresolver.SQLIdResolver.IdResolver.{admin_resolver_name}"
        )
        default_resolver_spec = (
            "useridresolver.PasswdIdResolver.IdResolver.def_resolver"
        )

        resolver_classes = ",".join(
            [default_resolver_spec, admin_resolver_spec]
        )
        with scoped_authclient(verify_jwt=False) as client:
            client.post(
                "/system/setRealm",
                data=dict(
                    realm=realm_name,
                    resolvers=resolver_classes,
                ),
            )

        # add a local admin
        LocalAdminResolver(base_app).add_user("test", "test")

        # login as user from realm myDefRes to get the cookies
        client.post(
            "/admin/login",
            data=dict(
                username="user1",
                password="geheim1",
            ),
        )

        cookies = client.cookie_jar._cookies["localhost.local"]["/"]

        # extract csrf token
        csrf_token = cookies.get("csrf_access_token").value

        # remove local admin resolver
        response = client.post(
            "/system/setRealm",
            headers={"X-CSRF-TOKEN": csrf_token},
            query_string={
                "realm": realm_name,
                "resolvers": admin_resolver_spec,
            },
        )

        error_message = (
            response.json.get("result", {}).get("error").get("message")
        )
        assert not response.json.get("result", {}).get("status")
        assert (
            "Resolver def_resolver must not removed from linotp_admins"
            in error_message
        )

        response = client.post(
            "/system/getRealms",
            headers={"X-CSRF-TOKEN": csrf_token},
        )

        resolvers_in_realm = response.json["result"]["value"][realm_name][
            "useridresolver"
        ]

        assert admin_resolver_spec in resolvers_in_realm
        assert default_resolver_spec in resolvers_in_realm

    def test_delete_local_admin_realm(
        self,
        base_app: LinOTPApp,
        scoped_authclient: Callable[..., FlaskClient],
    ) -> None:
        """
        Testing the deletion of the local admin realm
        """

        realm_name = base_app.config["ADMIN_REALM_NAME"].lower()

        with scoped_authclient(verify_jwt=False) as client:
            response = client.post(
                "/system/delRealm", data=dict(realm=realm_name)
            )

            assert response.json["result"]["status"] is False

            response_message = response.json["result"]["error"]["message"]
            assert (
                "It is not allowed to delete the admin realm"
                in response_message
            )
