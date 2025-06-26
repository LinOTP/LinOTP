import unittest
from collections import namedtuple

import pytest
from mock import patch

from linotp.lib.policy import PolicyException
from linotp.lib.policy.maxtoken import (
    calculate_token_limit,
    check_maxtoken_for_user,
    check_maxtoken_for_user_by_type,
)

User = namedtuple("User", ["login"])
Token = namedtuple("Token", ["type"])

fake_context = {}


def fake_get_client_policy(client, scope, action, realm, user, userObj):
    if realm == "defaultrealm":
        return {}

    if realm == "otherrealm":
        fake_policies = {
            "bla": {
                "realm": "*",
                "active": "True",
                "client": "",
                "user": "",
                "time": "",
                "action": "maxtoken=2, maxtokenPUSH=1, maxtokenHMAC",
                "scope": "enrollment",
            }
        }

        return fake_policies

    raise Exception(
        "fake_get_client_policy has no fake return value for realm %s" % realm
    )


@pytest.mark.usefixtures("app")
class MaxTokenPolicyTest(unittest.TestCase):
    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.context.request_context", new=fake_context)
    def test_no_or_empty_user(self):
        """
        checking if _checkTokenAssigned passes with empty user
        or None as user arguments
        """

        try:
            check_maxtoken_for_user(None)
        except PolicyException:
            assert not True, (
                "_checkTokenAssigned: None as argument should return without exception"
            )

        empty_user = User("")

        try:
            check_maxtoken_for_user(empty_user)
        except PolicyException:
            assert not True, (
                "_checkTokenAssigned: empty user as "
                "argument should return without exception"
            )

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.context.request_context", new=fake_context)
    @patch(
        "linotp.lib.policy.maxtoken.get_client_policy",
        new=fake_get_client_policy,
    )
    @patch("linotp.lib.policy.maxtoken.get_action_value")
    @patch("linotp.lib.policy.maxtoken._getUserRealms")
    @patch("linotp.lib.policy.maxtoken._get_client")
    @patch("linotp.lib.token.get_tokens")
    def test_no_tokens(
        self,
        mocked_get_tokens,
        mocked__get_client,
        mocked__getUserRealms,
        mocked_get_action_value,
    ):
        """
        checking if _checkTokenAssigned passes with empty token list
        """

        fake_user = User("fake_user")
        mocked_get_tokens.return_value = []
        mocked__get_client.return_value = "127.0.0.1"
        mocked__getUserRealms.return_value = ["defaultrealm", "otherrealm"]
        mocked_get_action_value.return_value = 2

        try:
            check_maxtoken_for_user(fake_user)
        except PolicyException:
            assert not True, (
                "_checkTokenAssigned: on empty token list "
                "function should return without exception"
            )

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.context.request_context", new=fake_context)
    @patch(
        "linotp.lib.policy.maxtoken.get_client_policy",
        new=fake_get_client_policy,
    )
    @patch("linotp.lib.policy.maxtoken.get_action_value")
    @patch("linotp.lib.policy.maxtoken._getUserRealms")
    @patch("linotp.lib.policy.maxtoken._get_client")
    @patch("linotp.lib.token.get_tokens")
    def test_maxtoken_all(
        self,
        mocked_get_tokens,
        mocked__get_client,
        mocked__getUserRealms,
        mocked_get_action_value,
    ):
        """
        checking if maxtoken policy works correctly
        """

        mocked_get_action_value.return_value = 2
        fake_user = User("fake_user")

        token1 = Token("hmac")
        token2 = Token("push")

        # want to enroll a second push
        mocked_get_tokens.return_value = [token1]
        mocked__get_client.return_value = "127.0.0.1"
        mocked__getUserRealms.return_value = ["defaultrealm", "otherrealm"]

        try:
            check_maxtoken_for_user(user=fake_user)
        except PolicyException:
            assert not True, (
                "_checkTokenAssigned: Exception raised, but "
                "token count was still in boundaries"
            )

        # third token exceeds maxtoken in fake_get_client_policy

        mocked_get_tokens.return_value = [token1, token2]

        exception_raised = False
        try:
            check_maxtoken_for_user(fake_user)
        except PolicyException:
            exception_raised = True

        if not exception_raised:
            assert not True, (
                "_checkTokenAssigned: Token count was not "
                "in boundaries but no exception was raised"
            )

        # second push token exceeds maxtokenPUSH in fake_get_client_policy

        mocked_get_tokens.return_value = [token2]
        mocked_get_action_value.return_value = 1

        exception_raised = False
        try:
            check_maxtoken_for_user_by_type(fake_user, type_of_token="push")
        except PolicyException:
            exception_raised = True

        if not exception_raised:
            assert not True, (
                "_checkTokenAssigned: Token count of PUSH "
                "was not in boundaries but no exception was "
                "raised"
            )


class MaxTokenAlgorithmTest(unittest.TestCase):
    def test_standard_case(self):
        max_token = [2]
        result = calculate_token_limit(max_token)
        assert result == 2

    def test_multiple_realms(self):
        max_token = [3, 2, True, -1]
        result = calculate_token_limit(max_token)
        assert result == 2

    def test_no_limits_set(self):
        max_token = [True, -1]
        result = calculate_token_limit(max_token)
        assert result is None
