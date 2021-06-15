from linotp.lib.ext.pbkdf2 import _makesalt


def test_urandom_import():
    """
    This test ensures that there are no import errors in _makesalt.
    """
    _makesalt()
