# Unit tests for the site_root_redirect
#
# This tests the app behavior when accessign the site root '/'
# with or without SITE_ROOT_REDIRECT config with the selfservice
# controller.

from urllib.parse import urlparse

import pytest


def path_equal(loc, path):
    return urlparse(loc).path == path


def test_redirect_manage(client):
    response = client.get("/")

    assert response.status_code == 302
    assert path_equal(response.headers["Location"], "/manage/")


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "manage:/my-custom-path",
    }
)
def test_redirect_custom_manage_url(client):
    response = client.get("/")

    assert response.status_code == 302
    assert path_equal(response.headers["Location"], "/my-custom-path/")


@pytest.mark.app_config(
    {
        "SITE_ROOT_REDIRECT": "/custom-site-redirect",
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
