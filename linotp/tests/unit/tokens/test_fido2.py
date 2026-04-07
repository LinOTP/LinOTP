"""Unit tests for FIDO2 token helper functions."""

from fido2.webauthn import AuthenticatorAttachment

from linotp.tokens.fido2token.fido2token import (
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
