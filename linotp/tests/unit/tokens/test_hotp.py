import json
import unittest

from mock import patch

from linotp.tokens.base import InvalidSeedException
from linotp.tokens.hmactoken import HmacTokenClass


class FakeTokenModel(object):
    def __init__(self, hashlib=None):
        self.info_dict = {}
        self.hashlib = hashlib

    def setType(self, typ):
        pass

    def getInfo(self):
        if self.hashlib:
            return json.dumps({"hashlib": self.hashlib})
        return ""


@patch("linotp.tokens.hmactoken.getFromConfig")
def test_hmac_hashlib_sha256(mock_getFromConfig):
    mock_getFromConfig.return_value = "sha1"
    hmac_token = HmacTokenClass(FakeTokenModel("sha256"))
    assert hmac_token.hashlibStr == "sha256"


@patch("linotp.tokens.hmactoken.getFromConfig")
def test_hmac_hashlib_sha1(mock_getFromConfig):
    mock_getFromConfig.return_value = "sha1"
    hmac_token = HmacTokenClass(FakeTokenModel())
    assert hmac_token.hashlibStr == "sha1"


class HmacTokenValidityTest(unittest.TestCase):
    @patch("linotp.tokens.hmactoken.getFromConfig")
    def test_validate_seed(self, moch_getFromConfig):
        """provided seed should be a valid HEX string"""

        hmac_token = HmacTokenClass(FakeTokenModel())
        goodseed = "1234ab18790bdef1234"
        hmac_token.validate_seed(goodseed)

        badseed = "1234ab18790bdef1234g"
        with self.assertRaises(InvalidSeedException) as cm:
            hmac_token.validate_seed(badseed)
        the_exception = cm.exception
        errormsg = "The provided token seed contains non-hexadecimal characters"
        self.assertEqual(errormsg, the_exception.msg)

        anotherbadseed = "1234ab187fH90bdef1234"
        with self.assertRaises(InvalidSeedException) as cm:
            hmac_token.validate_seed(anotherbadseed)
        the_exception = cm.exception
        errormsg = "The provided token seed contains non-hexadecimal characters"
        self.assertEqual(errormsg, the_exception.msg)
