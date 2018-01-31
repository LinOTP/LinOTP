# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

""" unit test for complex policy comparisons """

import unittest

from linotp.lib.policy.util import parse_action_value

class TestParseActionValue(unittest.TestCase):
    """
    unit tests for parsing action value
    """

    def test_parse_action_value(self):
        """
        test the parsing of acteion value
        """

        # ----------------------------------------------------------------- --

        # simple boolean parsing

        res_dict = {'delete': True}
        res = parse_action_value(', delete')
        assert(res == res_dict)

        res = parse_action_value(', delete , ')
        assert(res == res_dict)

        res = parse_action_value(', !delete , ')
        res_dict['delete'] = False
        assert(res == res_dict)

        # ----------------------------------------------------------------- --

        # simple key value parsing

        res_dict = {'otppin': '3'}
        res = parse_action_value('otppin=3,')
        assert(res == res_dict)

        res = parse_action_value(', otppin = 3')
        assert(res == res_dict)

        res = parse_action_value(', otppin=  3 , ')
        assert(res == res_dict)

        # ----------------------------------------------------------------- --

        # parse complex text with separtors

        res_dict = {'voice_message' :"Sir, your otp is {otp}"}
        res = parse_action_value('voice_message="Sir, your otp is {otp}",')
        assert(res == res_dict)

        res_dict = {
            'voice_message' : "Sir, your otp is {otp}" ,
            "voice_language": ' Sir, your otp is {otp}'
            }
        res = parse_action_value('voice_message = "Sir, your otp is {otp}" ,'
                                 " voice_language = ' Sir, your otp is {otp}' , ")

        assert(res == res_dict)

        # ----------------------------------------------------------------- --

        # parse complex structure with boolean and complex text with seperators

        res_dict = {
            "otppin": '3',
            "enrollHMAC": False,
            'voice_message': "Sir, your otp is {otp}",
            "voice_language": ' Sir, your otp is {otp}',
            "delete": True}

        res = parse_action_value(', otppin=3,!enrollHMAC,'
                                 'voice_message="Sir, your otp is {otp}",'
                                 " voice_language = ' Sir, your otp is {otp}' , "
                                 "delete")
        assert(res == res_dict)

        res_dict = {'blub': '23, 4',
                    'delete': '12 ,  3',
                    'erase': True,
                    'del': True,
                    'blah': '234'}

        res = parse_action_value('erase , delete="12 ,  3",' "blah = '234' "
                                 ' , blub ="23, 4", del')

        assert(res == res_dict)

        return

    def test_parse_actionvalue_exception(self):
        """
        parse_action_value raises some parsing exceptions
        """

        with self.assertRaises(Exception) as exx:
            parse_action_value(', delete="12 ,  3')

        msg = "non terminated string value entry"
        assert msg in exx.exception.message

        with self.assertRaises(Exception) as exx:
            parse_action_value(', delete, delete ,')

        msg = "duplicate key defintion"
        assert msg in exx.exception.message


        with self.assertRaises(Exception) as exx:
            parse_action_value(', del=1, del = 4 ,')

        msg = "duplicate key defintion"
        assert msg in exx.exception.message

        return

# eof #
