from linotp.lib.crypto.utils import compare_password


def test_compare_password_legacy_des_crypt():
    """
    Test compare_password function with legacy Unix DES crypt format.

    Ensures Python 3.13 compatibility for legacy 13-character Unix crypt hashes
    (no $ prefix).
    """
    # Known working combination from def-passwd fixture
    # DES crypt format: salt="yn" + hash="0Zck2KDip6U" = "yn0Zck2KDip6U"
    assert compare_password("test123", "yn0Zck2KDip6U")

    # Negative tests
    assert not compare_password("wrongpass", "yn0Zck2KDip6U")
    assert not compare_password("Test123", "yn0Zck2KDip6U")
    assert not compare_password("", "yn0Zck2KDip6U")
