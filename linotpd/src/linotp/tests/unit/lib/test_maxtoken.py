
import unittest
from mock import patch
from collections import namedtuple

from linotp.lib.policy import _checkTokenAssigned
from linotp.lib.policy import PolicyException

User = namedtuple('User', ['login'])
Token = namedtuple('Token', ['type'])

fake_context = {'translate': lambda x: x}


def fake_get_client_policy(client, scope, realm, user, userObj):

    if realm == 'defaultrealm':
        return {}

    if realm == 'otherrealm':

        fake_policies = {'bla': {'realm': '*',
                                  'active': 'True',
                                  'client': '',
                                  'user': '',
                                  'time': '',
                                  'action': 'maxtoken=2, maxtokenPUSH=1, '
                                              'maxtokenHMAC',
                                  'scope': 'enrollment'}}

        return fake_policies

    raise Exception('fake_get_client_policy has no fake return value for '
                    'realm %s' % realm)


class MaxTokenPolicyTest(unittest.TestCase):

    def test_no_or_empty_user(self):

        """
        checking if _checkTokenAssigned passes with empty user
        or None as user arguments
        """

        try:
            _checkTokenAssigned(None)
        except PolicyException:
            assert not True, '_checkTokenAssigned: None as argument ' \
                                   'should return without exception'

        empty_user = User('')

        try:
            _checkTokenAssigned(empty_user)
        except PolicyException:
            assert not True, '_checkTokenAssigned: empty user as ' \
                                   'argument should return without exception'

    @patch('linotp.lib.token.getTokens4UserOrSerial')
    def test_no_tokens(self, mocked_getTokens4UserOrSerial):

        """
        checking if _checkTokenAssigned passes with empty token list
        """

        fake_user = User('fake_user')
        mocked_getTokens4UserOrSerial.return_value = []

        try:
            _checkTokenAssigned(fake_user)
        except PolicyException:
            assert not True, '_checkTokenAssigned: on empty token list ' \
                                   'function should return without exception'

    @patch('linotp.lib.policy.context', new=fake_context)
    @patch('linotp.lib.policy.get_client_policy', new=fake_get_client_policy)
    @patch('linotp.lib.policy._getUserRealms')
    @patch('linotp.lib.policy._get_client')
    @patch('linotp.lib.token.getTokens4UserOrSerial')
    def test_maxtoken_all(self,
                          mocked_getTokens4UserOrSerial,
                          mocked__get_client,
                          mocked__getUserRealms):

        """
        checking if maxtoken policy works correctly
        """

        fake_user = User('fake_user')

        token1 = Token('hmac')
        token2 = Token('push')

        mocked_getTokens4UserOrSerial.return_value = [token1, token2]
        mocked__get_client.return_value = '127.0.0.1'
        mocked__getUserRealms.return_value = ['defaultrealm', 'otherrealm']

        try:
            _checkTokenAssigned(fake_user)
        except PolicyException:
            assert not True, '_checkTokenAssigned: Exception raised, but ' \
                                   'token count was still in boundaries'

        # third token exceeds maxtoken in fake_get_client_policy

        token3 = Token('qr')
        mocked_getTokens4UserOrSerial.return_value = [token1, token2, token3]

        exception_raised = False
        try:
            _checkTokenAssigned(fake_user)
        except PolicyException:
            exception_raised = True

        if not exception_raised:
            assert not True, '_checkTokenAssigned: Token count was not ' \
                                   'in boundaries but no exception was raised'

        # second push token exceeds maxtokenPUSH in fake_get_client_policy

        mocked_getTokens4UserOrSerial.return_value = [token2, token2]

        exception_raised = False
        try:
            _checkTokenAssigned(fake_user)
        except PolicyException:
            exception_raised = True

        if not exception_raised:
            assert not True, '_checkTokenAssigned: Token count of PUSH ' \
                                   'was not in boundaries but no exception was ' \
                                   'raised'
