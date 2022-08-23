# Unit tests for the site_root_redirect
#
# This tests the app behavior when accessign the site root '/'
# with or without SITE_ROOT_REDIRECT config with the selfservice
# controller.

from urllib.parse import urlparse

import pytest


def path_equal(loc, path):
    return urlparse(loc).path == path


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "selfservice",
    }
)
def test_redirect_legacy_selfservice(client):
    response = client.get("/")

    assert response.status_code == 302
    assert path_equal(response.headers["Location"], "/selfservice-legacy/")


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "selfservice:/my-custom-path",
    }
)
def test_redirect_custom_legacy_selfservice_url(client):
    response = client.get("/")

    assert response.status_code == 302
    assert path_equal(response.headers["Location"], "/my-custom-path/")


@pytest.mark.app_config(
    {
        "SITE_ROOT_REDIRECT": "/custom-site-redirect",
        "ENABLE_CONTROLLERS": "selfservice",
    }
)
def test_custom_site_root_redirect_config(client):
    response = client.get("/")

    assert response.status_code == 302
    assert path_equal(response.headers["Location"], "/custom-site-redirect")


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "",
    }
)
def test_no_redirect(client):
    response = client.get("/")

    assert response.status_code == 404
    assert "Location" not in response.headers
