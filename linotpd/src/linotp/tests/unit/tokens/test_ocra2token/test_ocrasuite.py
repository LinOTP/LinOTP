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
import unittest
from linotp.tokens.ocra2token import OcraSuite



class OcraTest(unittest.TestCase):

    pin = '1234'
    pin_sha1 = bytes.fromhex('7110eda4d09e062aa5e4a390b0a572ac0d2c0220')


    fkey = bytes.fromhex('a74f89f9251eda9a5d54a9955be4569f9720abe8')
    key20h = '3132333435363738393031323334353637383930'
    key20 = bytes.fromhex(key20h)

    key32h = '3132333435363738393031323334353637383930313233343536373839303132'
    key32 = bytes.fromhex(key32h)
    key64h = ('313233343536373839303132333435363738393031323334353637383930'
              '313233343536373839303132333435363738393031323334353637383930'
              '31323334')
    key64 = bytes.fromhex(key64h)


    tests = [{'ocrasuite': 'OCRA-1:HOTP-SHA1-6:QN08',
              'key': key20,
              'keyh': key20h,
              'vectors': [
                  {'params': {'Q': '00000000'}, 'result': '237653'},
                  {'params': {'Q': '11111111'}, 'result': '243178'},
                  {'params': {'Q': '22222222'}, 'result': '653583'},
                  {'params': {'Q': '33333333'}, 'result': '740991'},
                  {'params': {'Q': '44444444'}, 'result': '608993'},
                  {'params': {'Q': '55555555'}, 'result': '388898'},
                  {'params': {'Q': '66666666'}, 'result': '816933'},
                  {'params': {'Q': '77777777'}, 'result': '224598'},
                  {'params': {'Q': '88888888'}, 'result': '750600'},
                  {'params': {'Q': '99999999'}, 'result': '294470'}
              ]
              },
             {'ocrasuite': 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
              'key': key32,
              'keyh': key32h,
              'vectors': [
                  {'params': {'C': 0, 'Q': '12345678'},
                   'result': '65347737'},
                  {'params': {'C': 1, 'Q': '12345678'},
                   'result': '86775851'},
                  {'params': {'C': 2, 'Q': '12345678'},
                   'result': '78192410'},
                  {'params': {'C': 3, 'Q': '12345678'},
                   'result': '71565254'},
                  {'params': {'C': 4, 'Q': '12345678'},
                   'result': '10104329'},
                  {'params': {'C': 5, 'Q': '12345678'},
                   'result': '65983500'},
                  {'params': {'C': 6, 'Q': '12345678'},
                   'result': '70069104'},
                  {'params': {'C': 7, 'Q': '12345678'},
                   'result': '91771096'},
                  {'params': {'C': 8, 'Q': '12345678'},
                   'result': '75011558'},
                  {'params': {'C': 9, 'Q': '12345678'},
                   'result': '08522129'}
              ]
              },
             {'ocrasuite': 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1',
              'key': key32,
              'keyh': key32h,
              'vectors': [
                  {'params': {'Q': '00000000'}, 'result': '83238735'},
                  {'params': {'Q': '11111111'}, 'result': '01501458'},
                  {'params': {'Q': '22222222'}, 'result': '17957585'},
                  {'params': {'Q': '33333333'}, 'result': '86776967'},
                  {'params': {'Q': '44444444'}, 'result': '86807031'}
              ]
              },

             {'ocrasuite': 'OCRA-1:HOTP-SHA512-8:C-QN08',
              'key': key64,
              'keyh': key64h,
              'vectors': [
                  {'params': {'C': '00000', 'Q': '00000000'},
                   'result': '07016083'},
                  {'params': {'C': '00001', 'Q': '11111111'},
                   'result': '63947962'},
                  {'params': {'C': '00002', 'Q': '22222222'},
                   'result': '70123924'},
                  {'params': {'C': '00003', 'Q': '33333333'},
                   'result': '25341727'},
                  {'params': {'C': '00004', 'Q': '44444444'},
                   'result': '33203315'},
                  {'params': {'C': '00005', 'Q': '55555555'},
                   'result': '34205738'},
                  {'params': {'C': '00006', 'Q': '66666666'},
                   'result': '44343969'},
                  {'params': {'C': '00007', 'Q': '77777777'},
                   'result': '51946085'},
                  {'params': {'C': '00008', 'Q': '88888888'},
                   'result': '20403879'},
                  {'params': {'C': '00009', 'Q': '99999999'},
                   'result': '31409299'}
              ]
              },
             {'ocrasuite': 'OCRA-1:HOTP-SHA512-8:QN08-T1M',
              'key': key64,
              'keyh': key64h,
              'vectors': [
                  {'params': {'Q': '00000000',
                              'T_precomputed': int('132d0b6', 16)},
                   'result': '95209754'},
                  {'params': {'Q': '11111111',
                              'T_precomputed': int('132d0b6', 16)},
                   'result': '55907591'},
                  {'params': {'Q': '22222222',
                              'T_precomputed': int('132d0b6', 16)},
                   'result': '22048402'},
                  {'params': {'Q': '33333333',
                              'T_precomputed': int('132d0b6', 16)},
                   'result': '24218844'},
                  {'params': {'Q': '44444444',
                              'T_precomputed': int('132d0b6', 16)},
                   'result': '36209546'},
              ]
              },
             ]

    
    
    def test_ocrasuite(self):
        '''
            test_ocrasuite: test the given ocra suite test set
        '''
        for test in self.tests:
            ocra = OcraSuite(test['ocrasuite'])
            key = test['key']
            for vector in test['vectors']:
                params = vector['params']
                result = vector['result']
                if ocra.P is not None:
                    params['P'] = self.pin
                if ocra.T is not None:
                    pass
                data = ocra.combineData(**params)
                otp = ocra.compute(data, key)
                assert otp == result
        return