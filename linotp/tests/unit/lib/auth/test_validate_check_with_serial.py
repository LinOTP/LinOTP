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
from linotp.lib.auth.validate import ValidationHandler

mocked_context = {'audit': {}}

class mocked_TokenHandler():

    def auto_assign_otp_only(self, *args, **kwargs):
        return False

class FakeToken():

    pass

def mocked_getTokens4UserOrSerial(
                               query_user=None,
                               serial=None,
                               token_type=None,
                               read_for_update=True):
    if serial and not query_user:
        return [FakeToken()]
    if not serial and query_user:
        return [FakeToken(), FakeToken()]

class TestCheckWithSerial(unittest.TestCase):
    """
    verify that the calling of checkUserPass with a serial number
    in the options should focus the search of the tokens only on this token
    with the serial number.
    """
     
    @patch("linotp.lib.auth.validate.context", mocked_context)
    @patch("linotp.lib.auth.validate.TokenHandler", mocked_TokenHandler)
    @patch("linotp.lib.auth.validate.getTokens4UserOrSerial",
           mocked_getTokens4UserOrSerial)
    @patch("linotp.lib.auth.validate.get_auth_forward_on_no_token")
    @patch("linotp.lib.auth.validate.ValidationHandler.checkTokenList")
    @patch("linotp.lib.auth.validate.get_auth_forward")
    @patch("linotp.lib.auth.validate.getUserId")
    def test_validate_check_with_serial(
            self, mocked_geUserId, mocked_get_auth_forward,
            mocked_checkTokenList, mocked_auth_forward_no_token):
        """
        test calling checkUserPass with serial in the list of optional args
        """
        # ------------------------------------------------------------------ --

        # test setup

        user = User('root', 'anywhere')
        passw = "Test123!"

        serial = 'tok123'
        options = {'serial': serial}

        mocked_auth_forward_no_token.return_value = True 
        mocked_geUserId.return_value = ('uid', 'resolver', 'resolverClass')
        mocked_get_auth_forward.return_value = None
        mocked_checkTokenList.return_value = True, None

        # ------------------------------------------------------------------ --

        # if serial was given, there should be only one token in the tokenlist
        # when calling of checkTokenList

        vh = ValidationHandler()
        _result = vh.checkUserPass(user, passw, options=options)

        call_args = mocked_checkTokenList.call_args
        token_list = call_args[0][0]
        assert len(token_list) == 1

        # ------------------------------------------------------------------ --

        # if no serial was given, there should be 2 token in the tokenlist
        # when calling of checkTokenList

        vh = ValidationHandler()
        _result = vh.checkUserPass(user, passw, options=None)

        call_args = mocked_checkTokenList.call_args
        token_list = call_args[0][0]
        assert len(token_list) > 1

        return
# eof #
