# Unit tests for the site_root_redirect
#
# This tests the app behavior when accessign the site root '/'
# with or without SITE_ROOT_REDIRECT config with the selfservice
# controller.

import pytest


@pytest.mark.app_config(
    {
        "CONTROLLERS": "selfservice",
    }
)
def test_redirect_legacy_selfservice(client):
    response = client.get("/")
    assert (
        response.headers["Location"] == "http://localhost/selfservice-legacy/"
    )
    assert response.status_code == 302


@pytest.mark.app_config(
    {
        "CONTROLLERS": "selfservice:/my-custom-path",
    }
)
def test_redirect_custom_legacy_selfservice_url(client):
    response = client.get("/")
    assert response.headers["Location"] == "http://localhost/my-custom-path/"
    assert response.status_code == 302


@pytest.mark.app_config(
    {
        "SITE_ROOT_REDIRECT": "/custom-site-redirect",
        "CONTROLLERS": "selfservice",
    }
)
def test_custom_site_root_redirect_config(client):
    response = client.get("/")
    assert (
        response.headers["Location"] == "http://localhost/custom-site-redirect"
    )
    assert response.status_code == 302


@pytest.mark.app_config(
    {
        "CONTROLLERS": "",
    }
)
def test_no_redirect(client):
    response = client.get("/")
    assert "Location" not in response.headers
    assert response.status_code == 404
