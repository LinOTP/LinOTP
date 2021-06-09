from linotp.lib.util import modhex_decode, modhex_encode


def test_mod2hex():
    m = "fifjgjgkhchb"
    h = "474858596061"
    assert modhex_encode(h) == m


def test_hex2mod():
    m = "fifjgjgkhchb"
    h = "474858596061"
    assert modhex_decode(m) == h
