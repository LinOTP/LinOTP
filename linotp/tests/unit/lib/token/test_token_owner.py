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
Tests the create of audit entries
"""

import unittest

import pytest
from mock import patch

from linotp.lib.error import TokenAdminError
from linotp.lib.token import TokenHandler
from linotp.lib.user import User


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

    @patch("linotp.lib.token.get_raw_tokens")
    @patch("linotp.lib.token.getUserId")
    def test_isTokenOwner_no_token(
        self, mocked_getUserId, mocked_get_raw_tokens
    ):
        """
        test if no token is found
        """

        mocked_getUserId.return_value = ("123", "res", "resC")
        mocked_get_raw_tokens.return_value = []

        serial = "fake_123_token"
        user = User(login="hans")

        th = TokenHandler()

        with pytest.raises(TokenAdminError) as exx:
            th.isTokenOwner(serial, user)

        error = exx.value
        assert error.id == 1102
        assert error.getDescription() == f"No token with serial {serial} found"

        return

    @patch("linotp.lib.token.get_token")
    @patch("linotp.lib.token.getUserId")
    def test_isTokenOwner_token_and_user(
        self, mocked_getUserId, mocked_get_token
    ):
        """
        test if token owner is found
        """

        serial = "fake_123_token"
        user = User(login="hans")

        mocked_getUserId.return_value = ("123", "res", "resC")
        mocked_get_token.return_value = FakeToken("123", "res", "resC")

        th = TokenHandler()

        res = th.isTokenOwner(serial, user)

        assert res

        return

    @patch("linotp.lib.token.get_token")
    @patch("linotp.lib.token.getUserId")
    def test_isTokenOwner_token_and_int_userid(
        self, mocked_getUserId, mocked_get_token
    ):
        """
        test if token owner is found
        """

        serial = "fake_123_token"
        user = User(login="hans")

        mocked_getUserId.return_value = (123, "res", "resC")
        mocked_get_token.return_value = FakeToken("123", "res", "resC")

        th = TokenHandler()

        res = th.isTokenOwner(serial, user)

        assert res

        return

    @patch("linotp.lib.token.get_token")
    @patch("linotp.lib.token.getUserId")
    def test_hasOwner_token_and_user(self, mocked_getUserId, mocked_get_token):
        """
        test if token hasOwner
        """

        serial = "fake_123_token"
        user = User(login="hans")

        mocked_getUserId.return_value = ("123", "res", "resC")
        mocked_get_token.return_value = FakeToken("123", "res", "resC")

        th = TokenHandler()

        res = th.hasOwner(serial)

        assert res

        return

    @patch("linotp.lib.token.get_token")
    def test_hasOwner_token_and_root_user(self, mocked_get_token):
        """
        test if token hasOwner
        """

        serial = "fake_123_token"

        mocked_get_token.return_value = FakeToken("0", "res", "resC")

        th = TokenHandler()

        res = th.hasOwner(serial)

        assert res

        return

    @patch("linotp.lib.token.get_token")
    def test_hasOwner_token_and_no_user(self, mocked_get_token):
        """
        test if token hasOwner with user is 0,0,0
        """

        serial = "fake_123_token"

        mocked_get_token.return_value = FakeToken(None, "res", "resC")

        th = TokenHandler()

        res = th.hasOwner(serial)

        assert res == False

        return


# eof #
