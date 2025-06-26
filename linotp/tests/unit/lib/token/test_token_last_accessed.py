#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
Tests the last_access token info
"""

import unittest
from datetime import datetime
from unittest.mock import patch

from linotp.lib.token import add_last_accessed_info

# -------------------------------------------------------------------------- --

# we use a fake token which supports the interface: addToTokenInfo


class dbToken:
    def __init__(self):
        self.LinOtpLastAuthSuccess = ""
        self.LinOtpLastAuthMatch = ""


class FakeToken:
    def __init__(self):
        self.info = {}
        self.token = dbToken()

    def addToTokenInfo(self, key, value):
        self.info[key] = value

    def getFromTokenInfo(self, key, fallback=None):
        return self.info.get(key, fallback)

    def removeFromTokenInfo(self, key):
        if key in self.info:
            del self.info[key]


class TestTokenLastAcces(unittest.TestCase):
    """
    test for last token accessed info
    """

    @patch("linotp.lib.token.getFromConfig")
    def test_add_last_accessed_info_boolean(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "True"

        token_list = [FakeToken() for _i in range(1, 5)]

        add_last_accessed_info(token_list)

        for token in token_list:
            assert token.token.LinOtpLastAuthMatch != ""

        return

    @patch("linotp.lib.token.getFromConfig")
    def test_add_last_accessed_info_timeformat(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        custom_time_format = "%d.%m.%Y"
        m_getFromConfig.return_value = custom_time_format

        token_list = [FakeToken() for _i in range(1, 5)]

        add_last_accessed_info(token_list)

        for token in token_list:
            access_time = token.token.LinOtpLastAuthMatch
            assert isinstance(access_time, datetime)
        return

    @patch("linotp.lib.token.getFromConfig")
    def test_add_last_accessed_info_False(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "False"

        token_list = [FakeToken() for _i in range(1, 5)]

        add_last_accessed_info(token_list)

        for token in token_list:
            assert not token.token.LinOtpLastAuthMatch
        return

    @patch("linotp.lib.token.getFromConfig")
    def test_add_last_accessed_info_false(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "False"

        token_list = [FakeToken() for _i in range(1, 5)]

        add_last_accessed_info(token_list)

        for token in token_list:
            assert not token.token.LinOtpLastAuthMatch

        return

    @patch("linotp.lib.token.getFromConfig")
    def test_add_last_accessed_info_none(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = None

        token_list = [FakeToken() for _i in range(1, 5)]

        add_last_accessed_info(token_list)

        for token in token_list:
            assert not token.token.LinOtpLastAuthMatch

        return


# eof #
