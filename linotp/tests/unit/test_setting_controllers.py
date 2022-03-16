# Unit tests for setting the controllers and the site_root_redirect
#
# This test verifies the ENABLE_CONTROLLERS and DISABLE_CONTROLLERS
# settings are evaluated.
#
# Remark for the gettoken controller test:
# for all the tests the gettoken controller is enabled by default
# (s.conftest.py). Thus we explicit test the settings.py defaults here


import pytest


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "ALL",
        "DISABLE_CONTROLLERS": "",
    }
)
def test_all_controllers__are_accessible(client):
    response = client.get("/userservice/login")
    assert response.status_code == 200


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "ALL selfservice:/my-custom-path",
    }
)
def test_all_controllers_and_no_duplicate_selfservice(client):
    """test: all controllers and no selfservice duplicate error"""
    response = client.get("/")
    assert response.headers["Location"] == "http://localhost/my-custom-path/"
    assert response.status_code == 302

    response = client.get("/userservice/login")
    assert response.status_code == 200


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "selfservice",
    }
)
def test_no_other_controller_available(client):
    response = client.get("/")
    assert response.status_code == 302

    response = client.get("/userservice/login")
    assert response.status_code == 404


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "ALL",
        "DISABLE_CONTROLLERS": "",
    }
)
def test_gettoken_controller_accessible(client):
    response = client.get("/gettoken/getotp")
    assert response.status_code == 401
    assert not response.json["result"]["status"]


@pytest.mark.app_config(
    {
        "ENABLE_CONTROLLERS": "ALL",
        "DISABLE_CONTROLLERS": "gettoken",
    }
)
def test_gettoken_controller_not_accessible(client):
    response = client.get("/gettoken/getotp")
    assert response.status_code == 404
    assert response.status == "404 NOT FOUND"
