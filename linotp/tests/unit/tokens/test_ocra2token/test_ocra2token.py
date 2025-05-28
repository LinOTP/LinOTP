import unittest

from mock import patch

from linotp.tokens.ocra2token.ocra2token import get_qrtan_url


class Ocra2PolicyTest(unittest.TestCase):
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.tokens.ocra2token.ocra2token.getPolicy")
    def test_802_getqrtanurl(self, mock_getPolicy, mock_get_policy_definitions):
        """
        Policy 802: Testing Authentication Scope: the QR-TAN Url with a single realm
        """
        URL = "https://testserver/validate/check_t"
        policie_list = {
            "authQRTAN": {
                "name": "authQRTAN",
                "scope": "authentication",
                "realm": "testrealm",
                "action": "qrtanurl_init=%s" % URL,
            }
        }

        mock_getPolicy.return_value = policie_list
        mock_get_policy_definitions.return_value = {
            "authentication": {"qrtanurl_init": {"type": "str"}}
        }

        url = get_qrtan_url(qrtan_policy_name="qrtanurl_init", realms=["testrealm"])

        assert url == URL, url

        return

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.tokens.ocra2token.ocra2token.getPolicy")
    def test_803_getqrtanurl(self, mock_getPolicy, mock_get_policy_definitions):
        """
        Policy 803: Testing Authentication Scope: the QR-TAN Url with 3 realms
        """
        URL = "https://testserver/validate/check_t"

        policie_list = {
            "authQRTAN": {
                "name": "authQRTAN",
                "scope": "authentication",
                "realm": "testrealm, realm2, realm3",
                "action": "qrtanurl=%s" % URL,
            }
        }

        mock_get_policy_definitions.return_value = {
            "authentication": {"qrtanurl": {"type": "str"}}
        }

        mock_getPolicy.return_value = policie_list

        url = get_qrtan_url(qrtan_policy_name="qrtanurl", realms=["testrealm"])

        assert url == URL, url

        return
