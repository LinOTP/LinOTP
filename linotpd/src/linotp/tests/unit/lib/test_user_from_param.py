# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
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

import json
import unittest
from mock import patch

from linotp.lib.user import getUserFromParam


class TestGetFromParam(unittest.TestCase):

    test_sets = [
     {  # 1. test set with split @ off, user in no realm and no resolver
        'config': {
              'split@sign': 'false',
              'defaultRealm': 'DefRealm',
              'resolversOfUser': None,
              'realms': []},

        'runs': [{'params': {'user': 'amigo'},
                  'result': {'login': 'amigo', 'realm': 'DefRealm'}},

                 {'params': {'user': 'amigo', 'realm': 'mexico'},
                  'result': {'login': 'amigo', 'realm': 'mexico'}},

                 {'params': {'user': 'amigo@mexico'},
                  'result': {'login': 'amigo@mexico', 'realm': 'DefRealm'}},

                 {'params': {'user': 'amigo@mexico', 'realm': 'norway'},
                  'result': {'login': 'amigo@mexico', 'realm': 'norway'}},
                 ]},

     {  # 2. test set with split @ off, user in multiple realms and one resolver
        'config': {
              'split@sign': 'false',
              'defaultRealm': 'DefRealm',
              'resolversOfUser': ['mexRes'],
              'realms': ['mexico', 'DefRealm', 'norway']},

        'runs': [{'params': {'user': 'amigo'},
                  'result': {'login': 'amigo', 'realm': 'DefRealm'}},

                 {'params': {'user': 'amigo', 'realm': 'mexico'},
                  'result': {'login': 'amigo', 'realm': 'mexico'}},

                 {'params': {'user': 'amigo@mexico'},
                  'result': {'login': 'amigo@mexico', 'realm': 'DefRealm'}},

                 {'params': {'user': 'amigo@mexico', 'realm': 'norway'},
                  'result': {'login': 'amigo@mexico', 'realm': 'norway'}},

                 {'params': {'user': 'amigo@mexico', 'realm': 'china'},
                  'result': {'login': 'amigo@mexico', 'realm': 'china'}},
                 ]},

     {  # 3. test set with split @ on and
        #    resolver found in determined realm
        'config': {
              'split@sign': 'true',
              'defaultRealm': 'DefRealm',
              'resolversOfUser': ['mexRes'],
              'realms': []},
        'runs': [{'params': {'user': 'amigo'},
                  'result': {'login': 'amigo', 'realm': 'DefRealm'}},

                 {'params': {'user': 'amigo', 'realm': 'mexico'},
                  'result': {'login': 'amigo', 'realm': 'mexico'}},

                 {'params': {'user': 'amigo@mexico'},
                  'result': {'login': 'amigo', 'realm': 'mexico'}},

                 # ! error: realm correct, but login name splitted!
                 {'params': {'user': 'amigo@mexico', 'realm': 'norway'},
                  'result': {'login': 'amigo@mexico', 'realm': 'norway'}},
                 ]},

     {  # 4. test set with split @ on and
        #    resolver found in determined realm
        'config': {
              'split@sign': 'true',
              'defaultRealm': 'DefRealm',
              'resolversOfUser': ['mexRes'],
              'realms': ['mexico', 'DefRealm']},

        'runs': [{'params': {'user': 'amigo'},
                  'result': {'login': 'amigo', 'realm': 'DefRealm'}},

                 {'params': {'user': 'amigo', 'realm': 'mexico'},
                  'result': {'login': 'amigo', 'realm': 'mexico'}},

                 {'params': {'user': 'amigo@mexico'},
                  'result': {'login': 'amigo', 'realm': 'mexico'}},

                 # ! error: realm correct, but login name splitted!
                 {'params': {'user': 'amigo@mexico', 'realm': 'norway'},
                  'result': {'login': 'amigo@mexico', 'realm': 'norway'}},
                 ]},

    ]  # eof test sets

    @patch('linotp.lib.user.getRealms')
    @patch('linotp.lib.user.getResolversOfUser')
    @patch('linotp.lib.user.getDefaultRealm')
    @patch('linotp.lib.user.getFromConfig')
    def test_split_at_atsign(self,
                             mock_getFromConfig,
                             mock_getDefaultRealm,
                             mock_getResolversOfUser,
                             mock_getRealms):
        """
        test the test sets for split at @ sign
        """

        errors = []
        config_id = 0

        for test_set in self.test_sets:
            config_id += 1
            config = test_set['config']

            mock_getFromConfig.return_value = config['split@sign']
            mock_getDefaultRealm.return_value = config['defaultRealm']
            mock_getResolversOfUser.return_value = config['resolversOfUser']
            mock_getRealms.return_value = config['realms']

            # ------------------------------------------------------------- --
            run_id = 0
            for run in test_set['runs']:

                run_id += 1
                param = run['params']
                result = run['result']

                user = getUserFromParam(param)

                msg = ("Failed for config: %r\n at run[%r] %r\n"
                       "result was %r" % (config, run_id, run, user))

                try:

                    assert user.login == result['login'], msg
                    assert user.realm == result['realm'], msg

                except Exception as _exx:
                    errors.append(msg)

        # ----------------------------------------------------------------- --

        if errors:
            raise Exception(errors)

        return

    @patch('linotp.lib.user.getRealms')
    @patch('linotp.lib.user.getResolversOfUser')
    @patch('linotp.lib.user.getDefaultRealm')
    @patch('linotp.lib.user.getFromConfig')
    def document_split_at_atsign(self,
                                 mock_getFromConfig,
                                 mock_getDefaultRealm,
                                 mock_getResolversOfUser,
                                 mock_getRealms):
        """
        create documentation for the split at @sign behaviour
        """

        table = []

        raisedException = None

        config_id = 0

        for test_set in self.test_sets:
            config_id += 1
            config = test_set['config']

            mock_getFromConfig.return_value = config['split@sign']
            mock_getDefaultRealm.return_value = config['defaultRealm']
            mock_getResolversOfUser.return_value = config['resolversOfUser']
            mock_getRealms.return_value = config['realms']

            table.append('')
            cparams = json.dumps(config)
            cc = cparams.replace(
                '{', ' * ').replace(
                    ',', ' * ').replace(
                        '}', '')

            panel = ("{panel:title=Configuration|borderColor=blue|"
                     "titleBGColor=#708090|titleColor=white|bgColor=#dcdcdc}")
            cc = cc.replace(
                "true", 'Ja').replace(
                    "resolversOfUser", "User wird Resolver gefunden").replace(
                        "realms", "Benutzer ist in folgenden Realms")

            table.append('%s %s' % (panel, cc))
            table.append('')

            # ------------------------------------------------------------- --
            run_id = 0
            for run in test_set['runs']:

                run_id += 1
                param = run['params']

                user = getUserFromParam(param)

                jparams = json.dumps(param)
                pp = jparams.replace(
                    '{', '|* ').replace(
                        ',', ' * ').replace(
                            '}', '')

                result = {'login': user.login, 'realm': user.realm}
                rparams = json.dumps(result)
                rr = rparams.replace(
                    '{', '|* ').replace(
                        ',', ' * ').replace(
                            '}', '')

                table.append('||Parameters: %s||Result: %s|' % (pp, rr))

            table.append('{panel}')
            table.append('')

        with open('/tmp/split_at_atsign.txt', 'w') as ff:
            ff.write("\n".join(table).replace(
                ' * ', '\n* ').replace(
                    '[', '- ').replace(
                        ']', ''))

        # ----------------------------------------------------------------- --

        if raisedException:
            raise raisedException


# eof #