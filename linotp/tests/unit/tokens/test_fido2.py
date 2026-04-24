"""Unit tests for FIDO2 token helper functions."""

from types import SimpleNamespace
from unittest.mock import patch

from fido2.webauthn import AuthenticatorAttachment

from linotp.tokens.fido2token.fido2token import (
    _get_aggregated_fido2_policy_values,
    compute_authenticator_types_options,
)


def test_security_key_only():
    """security-key only → cross-platform attachment, hints=[security-key]"""
    result = compute_authenticator_types_options(["security-key"])
    assert result["authenticator_attachment"] == AuthenticatorAttachment.CROSS_PLATFORM
    assert result["hints"] == ["security-key"]


def test_client_device_only():
    """client-device only → platform attachment, hints=[client-device]"""
    result = compute_authenticator_types_options(["client-device"])
    assert result["authenticator_attachment"] == AuthenticatorAttachment.PLATFORM
    assert result["hints"] == ["client-device"]


def test_security_key_and_client_device():
    """security-key + client-device → no attachment restriction, both hints"""
    result = compute_authenticator_types_options(["security-key", "client-device"])
    assert "authenticator_attachment" not in result
    assert result["hints"] == ["security-key", "client-device"]


def test_empty_list():
    """empty list → empty dict (no hints, no attachment)"""
    result = compute_authenticator_types_options([])
    assert result == {}


def test_invalid_values_only():
    """invalid values only → empty dict"""
    result = compute_authenticator_types_options(["invalid", "foo"])
    assert result == {}


def test_hybrid_and_security_key():
    """hybrid + security-key → cross-platform attachment, both hints"""
    result = compute_authenticator_types_options(["hybrid", "security-key"])
    assert result["authenticator_attachment"] == AuthenticatorAttachment.CROSS_PLATFORM
    assert result["hints"] == ["hybrid", "security-key"]


def test_all_three_types():
    """all three types → no attachment restriction, all hints"""
    result = compute_authenticator_types_options(
        ["client-device", "security-key", "hybrid"]
    )
    assert "authenticator_attachment" not in result
    assert result["hints"] == ["client-device", "security-key", "hybrid"]


# ---------------------------------------------------------------------- --
# _get_aggregated_policy_values tests
# ---------------------------------------------------------------------- --

_MODULE = "linotp.tokens.fido2token.fido2token"
_ACTION = "fido2_allowed_authenticators"


def _make_policy(name, action, value):
    """Build a policy dict the way get_client_policy returns it."""
    return {name: {"name": name, "action": f"{action}={value}"}}


def _call_aggregated(policies, action=_ACTION):
    """Call _get_aggregated_policy_values with real get_action_value.

    Only ``get_client_policy``, ``context``, and ``get_policy_definitions``
    are patched.  ``get_action_value`` runs for real so the aggregation
    logic is actually exercised end-to-end.
    """
    user = SimpleNamespace(login="testuser", realm="testrealm")
    with (
        patch(f"{_MODULE}.context", {"Client": "127.0.0.1"}),
        patch(f"{_MODULE}.get_client_policy", return_value=policies),
        patch(
            "linotp.lib.policy.action.get_policy_definitions",
            return_value={"enrollment": {}},
        ),
    ):
        return _get_aggregated_fido2_policy_values(action, user)


def test_aggregated_none_user_returns_empty():
    assert _get_aggregated_fido2_policy_values("action", None) == []


def test_aggregated_no_policies_returns_empty():
    assert _call_aggregated(policies={}) == []


def test_aggregated_single_policy_splits_and_lowercases():
    policies = _make_policy("pol1", _ACTION, "AABB-1111 CCDD-2222")
    result = _call_aggregated(policies)
    assert sorted(result) == ["aabb-1111", "ccdd-2222"]


def test_aggregated_three_policies_merged_and_deduplicated():
    policies = {
        **_make_policy("pol1", _ACTION, "AAAA-1111 BBBB-2222"),
        **_make_policy("pol2", _ACTION, "CCCC-3333"),
        **_make_policy("pol3", _ACTION, "DDDD-4444 AAAA-1111"),
    }
    result = _call_aggregated(policies)
    # AAAA-1111 appears in pol1 and pol3 but must appear only once
    assert sorted(result) == ["aaaa-1111", "bbbb-2222", "cccc-3333", "dddd-4444"]


def test_aggregated_empty_value_skipped():
    policies = {
        **_make_policy("pol1", _ACTION, "AAAA"),
        # pol2 has the action key but no value — get_action_value returns ""
        "pol2": {"name": "pol2", "action": ""},
    }
    result = _call_aggregated(policies)
    assert result == ["aaaa"]


def test_aggregated_case_insensitive_dedup():
    policies = {
        **_make_policy("pol1", _ACTION, "AaAa"),
        **_make_policy("pol2", _ACTION, "aaaa"),
    }
    result = _call_aggregated(policies)
    assert result == ["aaaa"]
