import json
from mock import patch

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
