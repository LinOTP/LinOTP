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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""
Tests the create of audit entries
"""

import unittest
from mock import patch
from linotp.lib.user import User
from linotp.lib.token import TokenHandler
from linotp.lib.error import TokenAdminError
import pytest


class FakeToken:
    def __init__(self, login, res, resc):
        self.user = (login, res, resc)

    def getUser(self):
        return self.user


class TestTokenOwner(unittest.TestCase):
    """
    test coverage of the isTokenOwner
    """

    def test_isTokenOwner_user_is_None(self):
        """
        test if no user is given
        """

        serial = "fake_123_token"
        user = None

        th = TokenHandler()

        with pytest.raises(TokenAdminError) as exx:
            th.isTokenOwner(serial, user)

        exx.match("no user found")

        return

    def test_isTokenOwner_no_user(self):
        """
        test if no user is given
        """

        serial = "fake_123_token"
        user = User()

        th = TokenHandler()

        with pytest.raises(TokenAdminError) as exx:
            th.isTokenOwner(serial, user)

        exx.match("no user found")

        return

    @patch("linotp.lib.token.getTokens4UserOrSerial")
    @patch("linotp.lib.token.getUserId")
    def test_isTokenOwner_no_token(
        self, mocked_getUserId, mocked_getTokens4UserOrSerial
    ):
        """
        test if no token is found
        """

        mocked_getUserId.return_value = ("123", "res", "resC")
        mocked_getTokens4UserOrSerial.return_value = []

        serial = "fake_123_token"
        user = User(login="hans")

        th = TokenHandler()

        with pytest.raises(TokenAdminError) as exx:
            th.isTokenOwner(serial, user)

        exx.match("no token found")

        return

    @patch("linotp.lib.token.getTokens4UserOrSerial")
    @patch("linotp.lib.token.getUserId")
    def test_isTokenOwner_token_and_user(
        self, mocked_getUserId, mocked_getTokens4UserOrSerial
    ):
        """
        test if token owner is found
        """

        serial = "fake_123_token"
        user = User(login="hans")

        mocked_getUserId.return_value = ("123", "res", "resC")
        mocked_getTokens4UserOrSerial.return_value = [
            FakeToken("123", "res", "resC")
        ]

        th = TokenHandler()

        res = th.isTokenOwner(serial, user)

        assert res

        return

    @patch("linotp.lib.token.getTokens4UserOrSerial")
    @patch("linotp.lib.token.getUserId")
    def test_isTokenOwner_token_and_int_userid(
        self, mocked_getUserId, mocked_getTokens4UserOrSerial
    ):
        """
        test if token owner is found
        """

        serial = "fake_123_token"
        user = User(login="hans")

        mocked_getUserId.return_value = (123, "res", "resC")
        mocked_getTokens4UserOrSerial.return_value = [
            FakeToken("123", "res", "resC")
        ]

        th = TokenHandler()

        res = th.isTokenOwner(serial, user)

        assert res

        return

    @patch("linotp.lib.token.getTokens4UserOrSerial")
    @patch("linotp.lib.token.getUserId")
    def test_hasOwner_token_and_user(
        self, mocked_getUserId, mocked_getTokens4UserOrSerial
    ):
        """
        test if token hasOwner
        """

        serial = "fake_123_token"
        user = User(login="hans")

        mocked_getUserId.return_value = ("123", "res", "resC")
        mocked_getTokens4UserOrSerial.return_value = [
            FakeToken("123", "res", "resC")
        ]

        th = TokenHandler()

        res = th.hasOwner(serial)

        assert res

        return

    @patch("linotp.lib.token.getTokens4UserOrSerial")
    def test_hasOwner_token_and_root_user(self, mocked_getTokens4UserOrSerial):
        """
        test if token hasOwner
        """

        serial = "fake_123_token"

        mocked_getTokens4UserOrSerial.return_value = [
            FakeToken("0", "res", "resC")
        ]

        th = TokenHandler()

        res = th.hasOwner(serial)

        assert res

        return

    @patch("linotp.lib.token.getTokens4UserOrSerial")
    def test_hasOwner_token_and_no_user(self, mocked_getTokens4UserOrSerial):
        """
        test if token hasOwner with user is 0,0,0
        """

        serial = "fake_123_token"

        mocked_getTokens4UserOrSerial.return_value = [
            FakeToken(None, "res", "resC")
        ]

        th = TokenHandler()

        res = th.hasOwner(serial)

        assert res == False

        return


# eof #
