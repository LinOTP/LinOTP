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
Tests the last_access token info
"""

import unittest
from mock import patch

from linotp.lib.token import add_last_accessed_info

# -------------------------------------------------------------------------- --

# we use a fake token which supports the interface: addToTokenInfo

class FakeToken():

    def __init__(self):
        self.info = {}

    def addToTokenInfo(self, key, value):
        self.info[key] = value



class TestTokenLastAcces(unittest.TestCase):
    """
    test for last token accessed info
    """

    @patch('linotp.lib.token.getFromConfig')
    def test_add_last_accessed_info_boolean(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "True"

        token_list = []
        for _i in range(1,5):
            token_list.append(FakeToken())

        add_last_accessed_info([token_list])

        for token in token_list:
            assert 'last_access' in token.info
            assert ':' in token.info['last_access']

        return

    @patch('linotp.lib.token.getFromConfig')
    def test_add_last_accessed_info_timeformat(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "%d.%m.%Y"

        token_list = []
        for _i in range(1,5):
            token_list.append(FakeToken())

        add_last_accessed_info([token_list])

        for token in token_list:
            assert 'last_access' in token.info
            assert ':' not in token.info['last_access']

        return

    @patch('linotp.lib.token.getFromConfig')
    def test_add_last_accessed_info_False(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "False"

        token_list = []
        for _i in range(1,5):
            token_list.append(FakeToken())

        add_last_accessed_info([token_list])

        for token in token_list:
            assert not 'last_access' in token.info

        return

    @patch('linotp.lib.token.getFromConfig')
    def test_add_last_accessed_info_false(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = "False"

        token_list = []
        for _i in range(1,5):
            token_list.append(FakeToken())

        add_last_accessed_info([token_list])

        for token in token_list:
            assert not 'last_access' in token.info

        return

    @patch('linotp.lib.token.getFromConfig')
    def test_add_last_accessed_info_none(self, m_getFromConfig):
        """
        test if last accessed info is written into token info
        """

        m_getFromConfig.return_value = None

        token_list = []
        for _i in range(1,5):
            token_list.append(FakeToken())

        add_last_accessed_info([token_list])

        for token in token_list:
            assert not 'last_access' in token.info

        return

# eof #
